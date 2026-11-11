package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/southax/subfinder/v2/pkg/subscraping/sources/ndxer"
)

const (
	relatedURL = "https://api.ndxer.com/v1/related/"

	classSubject        = "subject"
	classReview         = "review"
	classInfrastructure = "infrastructure"

	// relatedMaxPages bounds paging for one seed, whatever the allowance says.
	relatedMaxPages = 200
)

// relatedBannerWriter receives the per-seed banner and related-scope notices.
// It is os.Stderr and never gologger: gologger's only level that survives
// -silent writes to stdout, which would pollute pipes.
var relatedBannerWriter io.Writer = os.Stderr

// relatedTag marks a domain that was added to the run because ndxer links it
// to a seed the user passed.
type relatedTag struct {
	Seed     string
	Class    string
	Why      string
	Evidence []ndxerEvidence
}

// relatedSettings is what an enabled expansion needs; nil on a Runner means off.
type relatedSettings struct {
	key     string
	classes []string
}

type relatedAPIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *relatedAPIError) Error() string {
	if e.Code != "" {
		if e.RequestID != "" {
			return fmt.Sprintf("ndxer related lookup failed: %s: %s (HTTP %d, request_id=%s)", e.Code, e.Message, e.Status, e.RequestID)
		}
		return fmt.Sprintf("ndxer related lookup failed: %s: %s (HTTP %d)", e.Code, e.Message, e.Status)
	}
	return fmt.Sprintf("ndxer related lookup failed: HTTP %d", e.Status)
}

// fatal reports whether the error will repeat for every further seed.
func (e *relatedAPIError) fatal() bool {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusPaymentRequired:
		return true
	}
	return false
}

type relatedPage struct {
	Meta struct {
		// Status is "partial" on a first page that is valid but not complete yet.
		Status          string  `json:"status"`
		NextCursor      *string `json:"next_cursor"`
		UnitsCharged    int     `json:"units_charged"`
		UnitsToComplete *int    `json:"units_to_complete"`
		UnitsRemaining  *int    `json:"units_remaining"`
	} `json:"meta"`
	Seed struct {
		Signals []struct {
			Class string `json:"class"`
		} `json:"signals"`
	} `json:"seed"`
	Matches []struct {
		Apex     string        `json:"apex"`
		Class    string        `json:"class"`
		Evidence []apiEvidence `json:"evidence"`
		Reasons  []struct {
			Code string `json:"code"`
			Text string `json:"text"`
		} `json:"reasons"`
	} `json:"matches"`
}

// apiEvidence is one evidence row of a /v1/related/ match.
type apiEvidence struct {
	Kind         string  `json:"kind"`
	Key          string  `json:"key"`
	NApexes      int     `json:"n_apexes"`
	ProviderName *string `json:"provider_name"`
}

// ndxerEvidence is one value a related domain shares with the seed, as -oJ writes it.
type ndxerEvidence struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	N        int    `json:"n"`
	Provider string `json:"provider,omitempty"` // from provider_name when set
}

// matchEvidence converts a match's evidence in API order, leaving out entries
// whose kind is "name_label" unless that is the only kind present (then all
// entries are kept).
func matchEvidence(evidence []apiEvidence) []ndxerEvidence {
	if len(evidence) == 0 {
		return nil
	}
	allNameLabel := true
	for _, e := range evidence {
		if e.Kind != "name_label" {
			allNameLabel = false
			break
		}
	}
	var out []ndxerEvidence
	for _, e := range evidence {
		if e.Kind == "name_label" && !allNameLabel {
			continue
		}
		ev := ndxerEvidence{Kind: e.Kind, Key: e.Key, N: e.NApexes}
		if e.ProviderName != nil {
			ev.Provider = *e.ProviderName
		}
		out = append(out, ev)
	}
	return out
}

// relatedResult is everything one seed's lookup produced.
type relatedResult struct {
	// ByClass lists the matched domains per proposed class, in API order.
	ByClass map[string][]string
	// Why maps the normalised domain to the API's most decisive reason text.
	Why map[string]string
	// Evidence maps the normalised domain to the values it shares with the seed.
	Evidence map[string][]ndxerEvidence
	// InfrastructureSignals counts seed signals that are a provider's.
	InfrastructureSignals int
	Units                 int
	Pages                 int
	// Stopped is set when paging ended early; it says why.
	Stopped string
	// Partial is set when the list was read while ndxer was still adding to
	// it; PartialCapped when that was after the whole wait.
	Partial       bool
	PartialCapped bool
}

// normaliseDomain matches the normalisation expand() applies: lower-case,
// trimmed, trailing dot removed.
func normaliseDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

type relatedClient struct {
	baseURL string
	key     string
	http    *http.Client
	retry   ndxer.Backoff
}

func newRelatedClient(key string, timeout time.Duration) *relatedClient {
	return &relatedClient{baseURL: relatedURL, key: key, http: &http.Client{Timeout: timeout}, retry: ndxer.DefaultBackoff()}
}

// lookup follows meta.next_cursor to the end. A further page costs one unit,
// so it stops, keeping what it has, when the allowance cannot cover the rest.
func (c *relatedClient) lookup(ctx context.Context, seed string) (*relatedResult, error) {
	result := &relatedResult{
		ByClass:  map[string][]string{},
		Why:      map[string]string{},
		Evidence: map[string][]ndxerEvidence{},
	}
	cursor := ""
	var pendingWaited time.Duration
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		page, err := c.fetch(ctx, seed, cursor, &pendingWaited)
		var partialErr *ndxer.PartialError
		if errors.As(err, &partialErr) && page != nil {
			result.Partial, result.PartialCapped = true, partialErr.Capped
			err = nil
		}
		if err != nil {
			var apiErr *relatedAPIError
			if result.Pages > 0 && errors.As(err, &apiErr) && apiErr.Code == "quota_exceeded" {
				result.Stopped = "the monthly allowance ran out while paging"
				return result, nil
			}
			return result, err
		}
		result.Pages++
		result.Units += page.Meta.UnitsCharged
		if result.Pages == 1 {
			for _, signal := range page.Seed.Signals {
				if signal.Class == classInfrastructure {
					result.InfrastructureSignals++
				}
			}
		}
		for _, match := range page.Matches {
			class := strings.ToLower(match.Class)
			result.ByClass[class] = append(result.ByClass[class], match.Apex)

			domain := normaliseDomain(match.Apex)
			if _, exists := result.Evidence[domain]; !exists {
				result.Evidence[domain] = matchEvidence(match.Evidence)
				if len(match.Reasons) > 0 {
					result.Why[domain] = match.Reasons[0].Text
				}
			}
		}

		next := page.Meta.NextCursor
		if next == nil || *next == "" || *next == cursor {
			return result, nil
		}
		meta := page.Meta
		// Fail fast, as the ndxer source does: stop when the allowance left
		// cannot pay for the pages that remain.
		if meta.UnitsRemaining != nil && meta.UnitsToComplete != nil && *meta.UnitsToComplete > *meta.UnitsRemaining {
			result.Stopped = fmt.Sprintf("the remaining pages need %d more units and %d are left this month; kept the pages fetched so far", *meta.UnitsToComplete, *meta.UnitsRemaining)
			return result, nil
		}
		if meta.UnitsRemaining != nil && *meta.UnitsRemaining < 1 {
			result.Stopped = "no units are left this month for further pages; kept the pages fetched so far"
			return result, nil
		}
		if result.Pages >= relatedMaxPages {
			result.Stopped = fmt.Sprintf("stopped after %d pages", relatedMaxPages)
			return result, nil
		}
		cursor = *next
	}
}

func (c *relatedClient) fetch(ctx context.Context, seed, cursor string, pendingWaited *time.Duration) (*relatedPage, error) {
	var page *relatedPage
	retry := c.retry
	retry.NoWait = retry.NoWait || ndxer.NoWait()
	retry.Note = func(partial bool) {
		_, _ = fmt.Fprintln(relatedBannerWriter, ndxer.WaitNotice("related domains", seed, partial))
	}
	err := retry.Await(ctx, seed, pendingWaited, func() error {
		p, err := c.fetchOnce(ctx, seed, cursor)
		page = p
		return err
	})
	return page, err
}

func (c *relatedClient) fetchOnce(ctx context.Context, seed, cursor string) (*relatedPage, error) {
	params := url.Values{"q": {seed}}
	if cursor != "" {
		params.Set("cursor", cursor)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "subfinder")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ndxer.Retryable(redactKey(err, c.key), "")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusAccepted {
		return nil, &ndxer.PendingError{RetryAfter: resp.Header.Get("Retry-After")}
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := &relatedAPIError{Status: resp.StatusCode}
		var body errorBody
		if jsoniter.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) == nil {
			apiErr.Code, apiErr.Message = body.Error.Code, body.Error.Message
			apiErr.RequestID = body.Error.RequestID
		}
		if ndxer.RetryableStatus(resp.StatusCode) {
			return nil, ndxer.Retryable(apiErr, resp.Header.Get("Retry-After"))
		}
		return nil, apiErr
	}
	var page relatedPage
	if err := jsoniter.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, ndxer.Retryable(fmt.Errorf("decode ndxer related response: %w", err), "")
	}
	if page.Meta.Status == ndxer.StatusPartial {
		return &page, &ndxer.PendingError{RetryAfter: resp.Header.Get("Retry-After"), Partial: true}
	}
	return &page, nil
}

type errorBody struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func redactKey(err error, key string) error {
	if key == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), key, "***"))
}

// parseRelatedClasses validates -ndxer-related-classes. An empty list means subject.
func parseRelatedClasses(values []string) ([]string, error) {
	var classes []string
	for _, value := range values {
		for _, class := range strings.Split(value, ",") {
			class = strings.ToLower(strings.TrimSpace(class))
			switch class {
			case "":
			case classSubject, classReview:
				if !slices.Contains(classes, class) {
					classes = append(classes, class)
				}
			case classInfrastructure:
				return nil, errors.New("-ndxer-related-classes: infrastructure is never added; it is a provider's, not the subject's")
			default:
				return nil, fmt.Errorf("-ndxer-related-classes: unknown class %q (use subject or review)", class)
			}
		}
	}
	if len(classes) == 0 {
		classes = []string{classSubject}
	}
	return classes, nil
}

// related is the per-run expansion state. It is shared by the producer only.
type related struct {
	client  *relatedClient
	classes []string
	// seen holds every domain already queued: the user's own and the added.
	seen map[string]struct{}
	// off is set after an error that every further seed would repeat.
	off bool
}

type relatedJob struct {
	domain string
	tag    *relatedTag
	// done, when set, is released once this domain's enumeration is over.
	done *sync.WaitGroup
}

// finish releases done, so related domains may start once every seed is over.
func (j relatedJob) finish() {
	if j.done != nil {
		j.done.Done()
	}
}

// waitDone waits for wg, or until ctx ends.
func waitDone(ctx context.Context, wg *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// expand returns the domains to add for one seed, and writes the banner.
func (rel *related) expand(ctx context.Context, seed string) []relatedJob {
	if rel.off {
		return nil
	}
	result, err := rel.client.lookup(ctx, seed)
	if err != nil {
		var apiErr *relatedAPIError
		if errors.As(err, &apiErr) && apiErr.fatal() {
			rel.off = true
			bannerf("ndxer related scope: %s. Related-scope expansion is off for the rest of this run; the names under the domains you passed are still listed. Turn it off explicitly with -no-ndxer-related.", err)
		} else if ctx.Err() == nil {
			bannerf("ndxer related scope for %s: %s. Only the names under the domain you passed are listed for this seed.", seed, err)
		}
		if result == nil || len(result.ByClass) == 0 {
			return nil
		}
	}

	var jobs []relatedJob
	added := map[string]int{}
	var addedNames []string
	for _, class := range rel.classes {
		for _, apex := range result.ByClass[class] {
			domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(apex)), ".")
			if domain == "" || domain == strings.ToLower(seed) {
				continue
			}
			if _, ok := rel.seen[domain]; ok {
				continue
			}
			rel.seen[domain] = struct{}{}
			jobs = append(jobs, relatedJob{domain: domain, tag: &relatedTag{
				Seed:     seed,
				Class:    class,
				Why:      result.Why[domain],
				Evidence: result.Evidence[domain],
			}})
			added[class]++
			addedNames = append(addedNames, domain)
		}
	}
	printRelatedBanner(seed, rel.classes, result, added, addedNames)
	return jobs
}

func bannerf(format string, args ...any) {
	_, _ = fmt.Fprintf(relatedBannerWriter, "\n"+format+"\n\n", args...)
}

// evidenceGroup is one set of added domains sharing the same evidence values.
type evidenceGroup struct {
	Values  []ndxerEvidence
	Domains []string
}

// groupByEvidence groups addedNames by the evidence they share. The group key
// is the domain's evidence sorted by (kind, key) and joined as "kind\x00key\x01...".
// Domains keep the order of names. Groups are ordered by len(Domains)
// descending; ties keep first-appearance order (sort.SliceStable).
func groupByEvidence(names []string, evidence map[string][]ndxerEvidence) []evidenceGroup {
	groups := make(map[string]*evidenceGroup)
	var order []string // first-appearance order of group keys

	for _, name := range names {
		ev := evidence[name]
		sorted := make([]ndxerEvidence, len(ev))
		copy(sorted, ev)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Kind != sorted[j].Kind {
				return sorted[i].Kind < sorted[j].Kind
			}
			return sorted[i].Key < sorted[j].Key
		})
		var sb strings.Builder
		for i, v := range sorted {
			if i > 0 {
				sb.WriteRune('\x01')
			}
			sb.WriteString(v.Kind)
			sb.WriteRune('\x00')
			sb.WriteString(v.Key)
		}
		key := sb.String()
		if g, ok := groups[key]; ok {
			g.Domains = append(g.Domains, name)
		} else {
			groups[key] = &evidenceGroup{Values: sorted, Domains: []string{name}}
			order = append(order, key)
		}
	}

	out := make([]evidenceGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Domains) > len(out[j].Domains)
	})
	return out
}

// formatEvidenceValues renders the shared values as "kind key + kind key".
// Keys longer than 60 runes are truncated with a trailing ellipsis.
func formatEvidenceValues(values []ndxerEvidence) string {
	if len(values) == 0 {
		return "no listed values"
	}
	parts := make([]string, len(values))
	for i, v := range values {
		key := v.Key
		if len([]rune(key)) > 60 {
			key = string([]rune(key)[:60]) + "…"
		}
		parts[i] = v.Kind + " " + key
	}
	return strings.Join(parts, " + ")
}

// bannerGroupMax is how many evidence groups a banner shows before counting the rest.
const bannerGroupMax = 15

func printRelatedBanner(seed string, classes []string, result *relatedResult, added map[string]int, addedNames []string) {
	var sb strings.Builder
	rule := strings.Repeat("=", 78)
	sb.WriteString("\n" + rule + "\n")
	fmt.Fprintf(&sb, "ndxer related scope for %s\n", seed)

	total := len(addedNames)
	if total == 0 {
		sb.WriteString("  Added 0 related domains.\n")
	} else {
		parts := make([]string, 0, len(classes))
		for _, class := range classes {
			if added[class] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", added[class], class))
			}
		}
		fmt.Fprintf(&sb, "  Added %d domains ndxer links to the same owner (%s), listed with all selected sources:\n", total, strings.Join(parts, ", "))

		groups := groupByEvidence(addedNames, result.Evidence)

		// Compute digit width of the largest group size.
		maxSize := 0
		for _, g := range groups {
			if len(g.Domains) > maxSize {
				maxSize = len(g.Domains)
			}
		}
		width := len(fmt.Sprintf("%d", maxSize))

		shownGroups := groups
		if len(shownGroups) > bannerGroupMax {
			shownGroups = shownGroups[:bannerGroupMax]
		}
		for _, g := range shownGroups {
			values := formatEvidenceValues(g.Values)
			fmt.Fprintf(&sb, "    %*d share %s\n", width, len(g.Domains), values)
			domains := g.Domains
			if len(domains) > 6 {
				domains = domains[:6]
			}
			fmt.Fprintf(&sb, "    %s%s", strings.Repeat(" ", width+1), strings.Join(domains, " "))
			if len(g.Domains) > 6 {
				fmt.Fprintf(&sb, " … and %d more", len(g.Domains)-6)
			}
			sb.WriteString("\n")
		}
		if len(groups) > bannerGroupMax {
			remainingDomains := 0
			for _, g := range groups[bannerGroupMax:] {
				remainingDomains += len(g.Domains)
			}
			fmt.Fprintf(&sb, "    … and %d more domains in %d other groups\n", remainingDomains, len(groups)-bannerGroupMax)
		}
	}

	if !slices.Contains(classes, classReview) {
		if n := len(result.ByClass[classReview]); n > 0 {
			fmt.Fprintf(&sb, "  NOT added: %d review domains (weaker evidence of the same owner). Include them with: -ndxer-related-classes subject,review\n", n)
		}
	}
	if n := result.InfrastructureSignals; n > 0 {
		fmt.Fprintf(&sb, "  NOT added: %d shared signals belong to infrastructure providers, not to the subject; never added.\n", n)
	}
	if result.Stopped != "" {
		fmt.Fprintf(&sb, "  INCOMPLETE: %s.\n", result.Stopped)
	}
	if result.Partial {
		fmt.Fprintf(&sb, "  PARTIAL: %s\n", ndxer.PartialNotice("related domains", seed, result.PartialCapped, false))
	}
	if total > 0 {
		fmt.Fprintf(&sb, "  ndxer source: about 1 unit per page for each added domain (%d domains), charged on top of the units below.\n", total)
	}
	fmt.Fprintf(&sb, "  Units charged by the related lookup: %d (%d page", result.Units, result.Pages)
	if result.Pages != 1 {
		sb.WriteString("s")
	}
	sb.WriteString(")\n")
	sb.WriteString("  Turn off: -no-ndxer-related\n")
	sb.WriteString("  Inspect the evidence:\n")
	fmt.Fprintf(&sb, "    curl -s -H \"Authorization: Bearer $NDXER_API_KEY\" \"%s?q=%s\"\n", relatedURL, seed)
	fmt.Fprintf(&sb, "    https://ndxer.com/app/investigations/?q=%s\n", seed)
	sb.WriteString(rule + "\n\n")
	_, _ = io.WriteString(relatedBannerWriter, sb.String())
}
