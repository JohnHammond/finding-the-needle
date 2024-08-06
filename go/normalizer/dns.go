package main

import (
	"log"
	"strings"

	nlpb "github.com/bearlyrunning/FindingTheNeedle/go/generated/normalizedlogpb"
)

func (dn *DNSNormalizer) getInput() string {
	return dn.input
}

func (dn *DNSNormalizer) getBinaryOutput() string {
	return dn.binaryOutput
}

func (dn *DNSNormalizer) getJsonOutput() string {
	return dn.jsonOutput
}

func (dn *DNSNormalizer) normalize(line string) *nlpb.NormalizedLog {
	fields := strings.Split(line, ",")

	// Validate fields.
	if len(fields) != 8 {
		log.Printf("invalid number of fields found; expect 8, found %d: %s\n", len(fields), line)
		return nil
	}

	// log.Printf("normalizer/dns.go - normalize() function called\n");

	// log.Printf(" fields = %+v\n", fields);

	timeField := fields[0];
	// log.Printf(" timeField = %+s\n", timeField);

	// Parse and return `datetime` field with validateTime().
	timestamppb, err := validateTime(timeField);
	if err != nil {
		log.Printf("%v, skipping: %s\n", err, line)
		return nil;
	}
	// log.Printf(" timestamppb returned: %+v", timestamppb)


	// Parse and return `src_ip` field with validateIP().
	srcIpField := fields[2];
	// log.Printf(" srcIpField = %+s\n", srcIpField);
	validSrcIP, err := validateIP(srcIpField)
	if err != nil {
		log.Printf("%v, skipping: %s\n", err, line)
		return nil
	}
	// log.Printf(" validated srcIpField = %+s\n", validSrcIP);


	resolver_ip := fields[3];
	// Parse and return `resolver_ip` field with validateIP().
	// log.Printf(" resolver_ip = %+s\n", resolver_ip);
	validResolverIP, err := validateIP(resolver_ip)
	if err != nil {
		log.Printf("%v, skipping: %s\n", err, line)
		return nil
	}
	// log.Printf(" validated validResolverIP = %+s\n", validResolverIP);


	// Parse and return `query` field with validateQuery().
	query := fields[4];
	validQuery, err := validateQuery(query);
	if err != nil {
		log.Printf("%v, skipping: %s\n", err, line)
		return nil
	}
	// log.Printf(" validated query = %+s\n", validQuery);


	// <TODO: Implement me!>
	// Parse and return `return_code` field with validateReturnCode().
	return_code := fields[7];
	// log.Printf(" return_code = %+s\n", return_code);
	validateReturnCode, err := validateReturnCode(return_code)
	if err != nil {
		log.Printf("%v, skipping: %s\n", err, line)
		return nil
	}

	// log.Printf(" validateReturnCode = %+v\n", validateReturnCode);


	// <TODO: Implement me!>
	// Return a populated NormalizedLog proto message.
	return &nlpb.NormalizedLog{
		Msg: &nlpb.NormalizedLog_DnsLog{
			DnsLog: &nlpb.DNS{
				Timestamp:  timestamppb,
				SourceIp:   validSrcIP,
				ResolverIp: validResolverIP,
				Query:      validQuery,
				Type:       fields[5],
				Answer:     fields[6],
				ReturnCode: validateReturnCode,
				LogSource:  fields[1],
			},
		},
	}

}
