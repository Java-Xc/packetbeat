// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build ignore

package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"gopkg.in/yaml.v2"

	"github.com/pkg/errors"
)

var (
	outputFile          = flag.String("output", "ftd-processor.yml", "Output file")
	filesetFieldsBase   = "cisco.ftd"
	tmpFieldsFieldsBase = "_temp_.cisco"
)

const begin = `#*******************************************************************************
# Code generated by go generate. DO NOT EDIT.
#*******************************************************************************
`

const end = `#*******************************************************************************
# End of generated code.
#*******************************************************************************
`

const painless = `boolean isEmpty(def value) {
  return (value instanceof AbstractList? value.size() : value.length()) == 0;
}
def appendOrCreate(Map dest, String[] path, def value) {
 for (int i=0; i<path.length-1; i++) {
  dest = dest.computeIfAbsent(path[i], _ -> new HashMap());
 }
 String key = path[path.length - 1];
 def existing = dest.get(key);
 return existing == null?
  dest.put(key, value)
  : existing instanceof AbstractList?
    existing.add(value)
    : dest.put(key, new ArrayList([existing, value]));
}
def msg = ctx._temp_.orig_security;
def counters = new HashMap();
def dest = new HashMap();
ctx._temp_.cisco['security'] = dest;
for (entry in msg.entrySet()) {
 def param = params.get(entry.getKey());
 if (param == null) {
   continue;
 }
 param.getOrDefault('id', []).forEach( id -> counters[id] = 1 + counters.getOrDefault(id, 0) );
 if (!isEmpty(entry.getValue())) {
  param.getOrDefault('ecs', []).forEach( field -> appendOrCreate(ctx, field.splitOnToken('.'), entry.getValue()) );
  dest[param.target] = entry.getValue();
 }
}
if (ctx._temp_.cisco.message_id != "") return;
def best;
for (entry in counters.entrySet()) {
 if (best == null || best.getValue() < entry.getValue()) best = entry;
}
if (best != null) ctx._temp_.cisco.message_id = best.getKey();
`

type mappings struct {
	If     string
	Params map[string]*fieldMapping
	Lang   string
	Source string
}

type fieldMapping struct {
	name   string
	Target string
	ID     stringSet `yaml:",flow,omitempty"`
	ECS    stringSet `yaml:",flow,omitempty"`
}

func main() {
	if err := generate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, "Usage: gen [-output file.yml] <input.csv>\n")
	flag.PrintDefaults()
	os.Exit(1)
}

func generate() error {
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) == 0 || len(flag.Args()[0]) == 0 {
		return errors.New("no csv file provided")
	}
	csvFile := flag.Args()[0]
	fHandle, err := os.Open(csvFile)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", csvFile, err)
	}
	defer fHandle.Close()

	outHandle, err := os.Create(*outputFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", *outputFile, err)
	}
	defer outHandle.Close()

	mappings, err := loadMappings(fHandle)
	if err != nil {
		return fmt.Errorf("failed to load mappings from '%s': %v", csvFile, err)
	}
	mappings.If = "ctx._temp_?.orig_security != null"
	mappings.Lang = "painless"
	mappings.Source = painless
	processors := []map[string]interface{}{
		{
			"script": mappings,
		},
	}
	body, err := yaml.Marshal(processors)
	if err != nil {
		return fmt.Errorf("error marshalling output yaml: %v", err)
	}
	var content []byte
	content = append(content, begin...)
	content = append(content, body...)
	content = append(content, end...)
	n, err := outHandle.Write(content)
	if err != nil {
		return errors.Wrap(err, "failed writing output file")
	}
	if n != len(content) {
		return fmt.Errorf("short write on output file. expected=%d, written=%d", len(content), n)
	}
	return nil
}

func loadMappings(reader io.Reader) (m mappings, err error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1
	allIDs := newStringSet(nil)
	for lineNum := 1; ; lineNum++ {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, errors.Wrapf(err, "failed reading line %d", lineNum)
		}
		if len(record) < 3 {
			return m, fmt.Errorf("line %d has unexpected number of columns: %d", lineNum, len(record))
		}
		ids := newStringSet(record[1:2])
		m.merge(&fieldMapping{
			name:   record[2],
			ID:     ids,
			ECS:    newStringSet(makeTempFields(record[3:])),
			Target: snakeCase(record[2]),
		})
		allIDs.merge(ids)
	}

	// fields that are used by all IDs are equivalent to an empty ID list
	for k := range m.Params {
		if m.Params[k].ID.equal(allIDs) {
			m.Params[k].ID = newStringSet(nil)
		}
	}
	return m, nil
}

func (m *mappings) merge(f *fieldMapping) {
	if other, found := m.Params[f.name]; found {
		other.ID.merge(f.ID)
		other.ECS.merge(f.ECS)
		return
	}
	if m.Params == nil {
		m.Params = make(map[string]*fieldMapping)
	}
	m.Params[f.name] = f
}

func makeTempFields(fields []string) []string {
	for idx, field := range fields {
		if strings.Index(field, filesetFieldsBase) == 0 {
			fields[idx] = tmpFieldsFieldsBase + field[len(filesetFieldsBase):]
		}
	}
	return fields
}

func snakeCase(in string) string {
	// This is copied from the netflow input with two changes:
	//  - handle spaces
	//  - treat digits as uppercase
	if strings.ContainsRune(in, ' ') {
		in = strings.ReplaceAll(in, " ", "_")
	}
	if strings.ContainsRune(in, '_') {
		return strings.ToLower(in)
	}

	out := make([]rune, 0, len(in)+4)
	runes := []rune(in)
	upperCount := 1
	for _, r := range runes {
		lr := unicode.ToLower(r)
		isUpper := lr != r || (r >= '0' && r <= '9')
		if isUpper {
			if upperCount == 0 {
				out = append(out, '_')
			}
			upperCount++
		} else {
			if upperCount > 2 {
				// Some magic here:
				// NetFlow usually lowercases all but the first letter of an
				// acronym (Icmp) Except when it is 2 characters long: (IP).
				// In other cases, it keeps all caps, but if we have a run of
				// more than 2 uppercase chars, then the last char belongs to
				// the next word:
				// postNATSourceIPv4Address     : post_nat_source_ipv4_address
				// selectorIDTotalFlowsObserved : selector_id_total_flows_...
				out = append(out, '_')
				n := len(out) - 1
				out[n], out[n-1] = out[n-1], out[n]
			}
			upperCount = 0
		}
		out = append(out, lr)
	}
	return string(out)
}
