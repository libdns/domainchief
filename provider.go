// Package domainchief implements a DNS record management client compatible
// with the libdns interfaces for Domain Chief (https://domain.chief.app)
// hosted DNS.
//
// TXT records on `_acme-challenge` names holding an ACME challenge value are
// published and removed through the dedicated ACME challenge endpoints, so
// solving ACME DNS-01 challenges only requires an API token with the
// `domainchief:acme:write` scope. All other operations use the DNS record
// endpoints: reading records requires the `domainchief:dns:read` scope and
// changing them requires the `domainchief:dns:write` scope, which includes
// `domainchief:dns:read`. ListZones requires the `domainchief:domains:read`
// scope.
package domainchief

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Domain Chief hosted DNS.
//
// The zone passed to the methods is the domain name in Domain Chief, for example `example.com.`.
// The domain must use hosted DNS.
type Provider struct {
	// APIToken is a Domain Chief API token. Create one at https://account.chief.app/team/select/token/create.
	//
	// For ACME DNS-01 challenges only the `domainchief:acme:write` scope is needed.
	APIToken string `json:"api_token,omitempty"`

	// BaseURL overrides the Domain Chief API base URL, defaults to DefaultBaseURL.
	BaseURL string `json:"base_url,omitempty"`

	// HTTPClient overrides the HTTP client used for API requests.
	HTTPClient *http.Client `json:"-"`

	// WaitForPublication makes AppendRecords wait until every hosted DNS nameserver serves the ACME challenge
	// values it publishes, so the certificate authority can validate them right away. This usually takes one to
	// three minutes and at most 10 minutes. Other records are never waited for.
	//
	// Leave it disabled when your ACME client checks the nameservers itself. That check only reaches the
	// nameservers near you, which can serve a value before the certificate authority's nameservers do.
	WaitForPublication bool `json:"wait_for_publication,omitempty"`

	zoneLocks sync.Map
}

// GetRecords lists all the records in the zone.
//
// Record types without a libdns struct type (ALIAS and TLSA) are returned as libdns.RR.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	existing, err := p.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	records := make([]libdns.Record, 0, len(existing))

	for _, record := range existing {
		records = append(records, toLibdns(record))
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
//
// ACME challenge TXT records on `_acme-challenge` names are published through the ACME challenge endpoint,
// which keeps other values on the same name and returns the existing record when the value is already published.
// With WaitForPublication enabled, AppendRecords then waits until every hosted DNS nameserver serves the
// challenge values.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	inputs := make([]recordInput, len(records))

	for i, record := range records {
		input, err := toInput(record)
		if err != nil {
			return nil, err
		}

		inputs[i] = input
	}

	appended := make([]libdns.Record, 0, len(records))
	var publishing []apiChallenge

	for i, record := range records {
		rr := record.RR()

		if isACMEChallenge(rr) {
			challenge, err := p.presentChallenge(ctx, libdns.AbsoluteName(rr.Name, zone), rr.Data)
			if err != nil {
				return appended, err
			}

			if p.WaitForPublication && challenge.Status != challengeStatusPublished {
				publishing = append(publishing, challenge)
			}

			appended = append(appended, libdns.TXT{
				Name: rr.Name,
				TTL:  time.Duration(challenge.TTL) * time.Second,
				Text: challenge.Value,
			})

			continue
		}

		created, err := p.createRecord(ctx, zone, inputs[i])
		if err != nil {
			return appended, err
		}

		appended = append(appended, toLibdns(created))
	}

	return appended, p.waitUntilPublished(ctx, publishing)
}

// waitUntilPublished repeats publishing the ACME challenges until every hosted DNS nameserver serves them.
//
// Publishing is idempotent and returns the current status of the challenge. A challenge that failed or is
// not published in time is deleted, so publishing it again later starts over.
func (p *Provider) waitUntilPublished(ctx context.Context, challenges []apiChallenge) error {
	deadline := time.Now().Add(publishTimeout)

	for len(challenges) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(publishPollInterval):
		}

		var remaining []apiChallenge

		for _, challenge := range challenges {
			current, err := p.presentChallenge(ctx, challenge.Name, challenge.Value)
			if err != nil {
				return err
			}

			switch current.Status {
			case challengeStatusPublished:
				continue
			case challengeStatusFailed:
				return p.abandonChallenge(ctx, challenge, "could not be added to the hosted DNS zone")
			}

			if !time.Now().Before(deadline) {
				return p.abandonChallenge(ctx, challenge, fmt.Sprintf("is not served by every nameserver after %s", publishTimeout))
			}

			remaining = append(remaining, challenge)
		}

		challenges = remaining
	}

	return nil
}

func (p *Provider) abandonChallenge(ctx context.Context, challenge apiChallenge, reason string) error {
	err := fmt.Errorf("domain chief: ACME challenge %s %s", challenge.Name, reason)

	if cleanUpErr := p.cleanUpChallenge(ctx, challenge.Name, challenge.Value); cleanUpErr != nil {
		return errors.Join(err, cleanUpErr)
	}

	return err
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the records that were set.
//
// For every (name, type) pair in the input, existing records with the same value are kept, other existing
// records are updated to hold the remaining values and leftover records are deleted. This is not atomic,
// when an error is returned some of the changes may have been applied.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	type rrset struct {
		inputs  []recordInput
		current []apiRecord
	}

	sets := map[string]*rrset{}
	var order []string

	for _, record := range records {
		input, err := toInput(record)
		if err != nil {
			return nil, err
		}

		key := input.Name + "|" + input.Type

		if sets[key] == nil {
			sets[key] = &rrset{}
			order = append(order, key)
		}

		sets[key].inputs = append(sets[key].inputs, input)
	}

	unlock := p.lockZone(zone)
	defer unlock()

	existing, err := p.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	for _, record := range existing {
		key := strings.ToLower(record.Name) + "|" + strings.ToUpper(record.Type)

		if set := sets[key]; set != nil {
			set.current = append(set.current, record)
		}
	}

	var results []libdns.Record

	for _, key := range order {
		set := sets[key]
		used := make([]bool, len(set.current))
		var pending []recordInput

		for _, input := range set.inputs {
			index := -1

			for i, current := range set.current {
				if !used[i] && sameContent(current, input) {
					index = i

					break
				}
			}

			if index < 0 {
				pending = append(pending, input)

				continue
			}

			used[index] = true
			record := set.current[index]

			if record.TTL != input.TTL {
				if record, err = p.updateRecord(ctx, zone, record.ID, input); err != nil {
					return results, err
				}
			}

			results = append(results, toLibdns(record))
		}

		var leftovers []apiRecord

		for i, current := range set.current {
			if !used[i] {
				leftovers = append(leftovers, current)
			}
		}

		for _, input := range pending {
			var record apiRecord

			if len(leftovers) > 0 {
				record, err = p.updateRecord(ctx, zone, leftovers[0].ID, input)
				leftovers = leftovers[1:]
			} else {
				record, err = p.createRecord(ctx, zone, input)
			}

			if err != nil {
				return results, err
			}

			results = append(results, toLibdns(record))
		}

		for _, leftover := range leftovers {
			if err := p.deleteRecord(ctx, zone, leftover.ID); err != nil {
				return results, err
			}
		}
	}

	return results, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
//
// ACME challenge TXT records on `_acme-challenge` names with a value are removed through the ACME challenge
// endpoint. That endpoint does not report whether the value existed, so the input record is always returned.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record
	var remaining []libdns.Record

	for _, record := range records {
		rr := record.RR()

		if !isACMEChallenge(rr) {
			remaining = append(remaining, record)

			continue
		}

		if err := p.cleanUpChallenge(ctx, libdns.AbsoluteName(rr.Name, zone), rr.Data); err != nil && !isNotFound(err) {
			return deleted, err
		}

		deleted = append(deleted, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}

	if len(remaining) == 0 {
		return deleted, nil
	}

	unlock := p.lockZone(zone)
	defer unlock()

	existing, err := p.listRecords(ctx, zone)
	if err != nil {
		return deleted, err
	}

	for _, record := range existing {
		matched := false

		for _, candidate := range remaining {
			if matches(record, candidate) {
				matched = true

				break
			}
		}

		if !matched {
			continue
		}

		if err := p.deleteRecord(ctx, zone, record.ID); err != nil {
			return deleted, err
		}

		deleted = append(deleted, toLibdns(record))
	}

	return deleted, nil
}

// ListZones returns the domains in the team that use hosted DNS.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	domains, err := p.listDomains(ctx)
	if err != nil {
		return nil, err
	}

	var zones []libdns.Zone

	for _, domain := range domains {
		if domain.IsUsingHostedDNS {
			zones = append(zones, libdns.Zone{Name: domain.Domain + "."})
		}
	}

	return zones, nil
}

// lockZone serializes read-modify-write operations on a zone within this provider.
func (p *Provider) lockZone(zone string) func() {
	value, _ := p.zoneLocks.LoadOrStore(zoneDomain(zone), &sync.Mutex{})
	mutex := value.(*sync.Mutex)

	mutex.Lock()

	return mutex.Unlock
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
