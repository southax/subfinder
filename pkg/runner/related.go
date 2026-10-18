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
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
)

const (
	relatedURL = "https://api.ndxer.com/v1/related/"

	classSubject        = "subject"
	classReview         = "review"
	classInfrastructure = "infrastructure"

	// relatedMaxPages bounds paging for one seed, whatever the allowance says.
	relatedMaxPages = 200
	// bannerListMax is how many added domains a banner names before it counts the rest.
	bannerListMax = 40
)

// relatedBannerWriter receives the per-seed banner and related-scope notices.
// It is os.Stderr and never gologger: gologger's only level that survives
// -silent writes to stdout, which would pollute pipes.
var relatedBannerWriter io.Writer = os.Stderr

// relatedTag marks a domain that was added to the run because ndxer links it
// to a seed the user passed.
type relatedTag struct {
	Seed  string
	Class string
}

// relatedSettings is what an enabled expansion needs; nil on a Runner means off.
type relatedSettings struct {
	key     string
	classes []string
}

type relatedAPIError struct {
	Status  int
	Code    string
	Message string
}

func (e *relatedAPIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("ndxer related lookup failed: %s: %s (HTTP %d)", e.Code, e.Message, e.Status)
	}
	return fmt.Sprintf("ndxer related lookup failed: HTTP %d", e.Status)
}

// fatal reports whether the error will repeat for every further seed.
func (e *relatedAPIError) fatal() bool {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusPaymentRequired:
		return true
	}
	return false
}

type relatedPage struct {
	Meta struct {
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
		Apex  string `json:"apex"`
		Class string `json:"class"`
	} `json:"matches"`
}

// relatedResult is everything one seed's lookup produced.
type relatedResult struct {
	// ByClass lists the matched domains per proposed class, in API order.
	ByClass map[string][]string
	// InfrastructureSignals counts seed signals that are a provider's.
	InfrastructureSignals int
	Units                 int
	Pages                 int
	// Stopped is set when paging ended early; it says why.
	Stopped string
}

type relatedClient struct {
	baseURL string
	key     string
	http    *http.Client
}

func newRelatedClient(key string, timeout time.Duration) *relatedClient {
	return &relatedClient{baseURL: relatedURL, key: key, http: &http.Client{Timeout: timeout}}
}

// lookup follows meta.next_cursor to the end. A further page costs one unit,
// so it stops, keeping what it has, when the allowance cannot cover the rest.
func (c *relatedClient) lookup(ctx context.Context, seed string) (*relatedResult, error) {
	result := &relatedResult{ByClass: map[string][]string{}}
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		page, err := c.fetch(ctx, seed, cursor)
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

func (c *relatedClient) fetch(ctx context.Context, seed, cursor string) (*relatedPage, error) {
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
		return nil, redactKey(err, c.key)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		apiErr := &relatedAPIError{Status: resp.StatusCode}
		var body errorBody
		if jsoniter.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) == nil {
			apiErr.Code, apiErr.Message = body.Error.Code, body.Error.Message
		}
		return nil, apiErr
	}
	var page relatedPage
	if err := jsoniter.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decode ndxer related response: %w", err)
	}
	return &page, nil
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
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
			bannerf("ndxer related scope: %s. Related-scope expansion is off for the rest of this run; the domains you passed are still enumerated. Turn it off explicitly with -no-ndxer-related.", err)
		} else if ctx.Err() == nil {
			bannerf("ndxer related scope for %s: %s. Only the domain you passed is enumerated for this seed.", seed, err)
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
			jobs = append(jobs, relatedJob{domain: domain, tag: &relatedTag{Seed: seed, Class: class}})
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
		fmt.Fprintf(&sb, "  Added %d domains ndxer links to the same owner (%s), enumerated with all selected sources:\n", total, strings.Join(parts, ", "))
		shown := addedNames
		if len(shown) > bannerListMax {
			shown = shown[:bannerListMax]
		}
		fmt.Fprintf(&sb, "    %s", strings.Join(shown, " "))
		if len(addedNames) > len(shown) {
			fmt.Fprintf(&sb, " ... and %d more", len(addedNames)-len(shown))
		}
		sb.WriteString("\n")
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
	fmt.Fprintf(&sb, "    https://ndxer.com/app/lookup/related/?q=%s\n", seed)
	sb.WriteString(rule + "\n\n")
	_, _ = io.WriteString(relatedBannerWriter, sb.String())
}
