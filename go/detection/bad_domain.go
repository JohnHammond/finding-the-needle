package main

import (
	"bufio"
	"fmt"
	"os"
	"log"
	"regexp"
	"strings"

	spb "github.com/bearlyrunning/FindingTheNeedle/go/generated/signalpb"
	nlpb "github.com/bearlyrunning/FindingTheNeedle/go/generated/normalizedlogpb"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const indicatorPath = "../../data/indicators/bad_domain.csv"

func (bdd *BadDomainDetection) ruleName() string {
	return bdd.name
}

func fmtRegex(ind []string) string {
	return fmt.Sprintf(".*(%s)$", strings.Join(ind, "|"))
}

func (bdd *BadDomainDetection) setFilterRegex() error {
	// Get the list of domain indicators.
	var ind []string
	f, err := os.Open(indicatorPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", indicatorPath, err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		ind = append(ind, strings.Split(s.Text(), ",")[0])
	}
	if err = s.Err(); err != nil {
		return fmt.Errorf("failed to scan file: %v", err)
	}
	// Compile a regex expression for matching indicators of compromise

	str := fmtRegex(ind)
	bdd.rr, err = regexp.Compile(str)
	if err != nil {
		return fmt.Errorf("failed compiling regex %s: %v", str, err)
	}
	return nil
}

func (bdd *BadDomainDetection) run() ([]*spb.Signal, error) {
	// Set regex for filtering.
	if err := bdd.setFilterRegex(); err != nil {
		return nil, err
	}

	matchedDomains := make([]*nlpb.DNS, 0)

	for _, log := range bdd.logs.dns {
		if bdd.rr.MatchString(log.Query) || bdd.rr.MatchString(log.Answer) {
			matchedDomains = append(matchedDomains, log)
		}
	}

	signals := make([]*spb.Signal,0)
	mapped_entries := make(map[string][]*nlpb.DNS,0)

	for _, matched_dns := range matchedDomains {
		mapped_entries[matched_dns.SourceIp] = append(mapped_entries[matched_dns.SourceIp], matched_dns)
	}

	for source_ip, dns_logs := range mapped_entries {

		// We will calculate the "latest" as we continue through the code

		earliest, latest := dns_logs[0].Timestamp.AsTime(), dns_logs[0].Timestamp.AsTime()
		for _, each_log := range dns_logs[1:] {
			if each_log.Timestamp.AsTime().Before(earliest) {
				earliest = each_log.Timestamp.AsTime()
				continue
			}
			if each_log.Timestamp.AsTime().After(latest) {
				latest = each_log.Timestamp.AsTime()
			}
		}


		bad_domain_regex_results := bdd.rr.FindStringSubmatch(dns_logs[0].Query)
		// If they did not the bad domain in the query, it must be in the answer
		if len(bad_domain_regex_results) == 0 {
			bad_domain_regex_results = bdd.rr.FindStringSubmatch(dns_logs[0].Answer)
		}

		signals = append(signals, &spb.Signal{
			Event: &spb.Signal_BadDomain{
				BadDomain: &spb.BadDomain{
					TimestampStart: tspb.New(earliest),
					TimestampEnd:   tspb.New(latest),
					BadDomain:      bad_domain_regex_results[1],
					SourceIp:       source_ip,
					DnsLog:         dns_logs,
				},
			},
		})

	}

	log.Printf("signals: %+v\n", signals)

	return signals, nil;



	// for _, log := range bdd.logs.dns {
	// 	found := bdd.rr.MatchString(log.Query)
	// 	if found {
	// 		fmt.Printf("matched on %+v\n", log.Query)

	// 		new_signal = &spb.Signal{
	// 			Event: &spb.Signal_BadDomain {
	// 				BadDomain: &spb.BadDomain{
	// 					TimestampStart: tspb.New(earliest),
	// 					TimestampEnd:   tspb.New(latest),
	// 					SourceIp:       log.Src_Ip,
	// 					BadDomain:      m[1],
	// 					DnsLog:         logs,
	// 				},
	// 			}
	// 		}
	// 		signals = append(signals, new_signal)
	// 	}
	// }

	// fmt.Printf("signals are: %+v", signals)

	// fmt.Printf("%+v", bdd.logs);
	// for _, log := range bdd.logs {
	// 	fmt.Printf("%+v", log);
	// } 
	

	// <TODO: Implement me!>
	// Find any logs that contain indicators of compromise from indicatorPath:
	//   1. Filter logs to what is relevant, then
	//   2. [Optional] Aggregate logs based on source IP address.
	//   3. Return the set of interesting logs as a list of spb.Signal

	// Expected output:
	// Option #1: If the aggregation step is skipped, the list of spb.Signal returned should have `event` field set to `bad_domain_filtered`.
	// Option #2: If both filtering and aggregation are performed, the list of spb.Signal returned should have `event` field set to `bad_domain`.

	// Hint #1: Make use of bdd.rr and the `regexp` package.
	// Hint #2: Aggregation is easier using a map data structure.
	// Hint #3: Check the fields you need to populate by inspecting the spb.BadDomain protobuf message.
	// return nil, nil
}
