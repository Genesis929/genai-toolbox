// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bigquerycommon

import (
	"fmt"
	"strings"
	"unicode"
)

// parserState defines the state of the SQL parser's state machine.
type parserState int

const (
	stateNormal parserState = iota
	// String states
	stateInSingleQuoteString
	stateInDoubleQuoteString
	stateInTripleSingleQuoteString
	stateInTripleDoubleQuoteString
	stateInRawSingleQuoteString
	stateInRawDoubleQuoteString
	stateInRawTripleSingleQuoteString
	stateInRawTripleDoubleQuoteString
	// Comment states
	stateInSingleLineCommentDash
	stateInSingleLineCommentHash
	stateInMultiLineComment
)

// SQL statement verbs
const (
	verbCreate = "create"
	verbAlter  = "alter"
	verbDrop   = "drop"
	verbSelect = "select"
	verbInsert = "insert"
	verbUpdate = "update"
	verbDelete = "delete"
	verbMerge  = "merge"
)

var tableFollowsKeywords = map[string]bool{
	"from":   true,
	"join":   true,
	"update": true,
	"into":   true, // INSERT INTO, MERGE INTO
	"table":  true, // CREATE TABLE, ALTER TABLE
	"using":  true, // MERGE ... USING
	"insert": true, // INSERT my_table
	"merge":  true, // MERGE my_table
}

var tableContextExitKeywords = map[string]bool{
	"where":  true,
	"group":  true, // GROUP BY
	"having": true,
	"order":  true, // ORDER BY
	"limit":  true,
	"window": true,
	"on":     true, // JOIN ... ON
	"set":    true, // UPDATE ... SET
	"when":   true, // MERGE ... WHEN
}

// TableParser is the main entry point for parsing a SQL string to find all referenced table IDs.
// It handles multi-statement SQL, comments, and recursive parsing of EXECUTE IMMEDIATE statements.
func TableParser(sql, defaultProjectID string) ([]string, error) {
	tableIDSet := make(map[string]struct{})
	visitedSQLs := make(map[string]struct{})
	aliases := make(map[string]struct{})
	if _, err := parseSQL(sql, defaultProjectID, tableIDSet, visitedSQLs, aliases, false); err != nil {
		return nil, err
	}

	tableIDs := make([]string, 0, len(tableIDSet))
	for id := range tableIDSet {
		isAlias := false
		parts := strings.Split(id, ".")
		for j := 0; j < len(parts); j++ {
			suffix := strings.ToLower(strings.Join(parts[j:], "."))
			if _, ok := aliases[suffix]; ok {
				isAlias = true
				break
			}
		}
		if !isAlias {
			tableIDs = append(tableIDs, id)
		}
	}
	return tableIDs, nil
}

// parseSQL is the core recursive function that processes SQL strings.
// It uses a state machine to find table names and recursively parse EXECUTE IMMEDIATE.
func parseSQL(sql, defaultProjectID string, tableIDSet map[string]struct{}, visitedSQLs map[string]struct{}, aliases map[string]struct{}, inSubquery bool) (int, error) {
	// Prevent infinite recursion.
	if _, ok := visitedSQLs[sql]; ok {
		return len(sql), nil
	}
	visitedSQLs[sql] = struct{}{}

	state := stateNormal
	expectingTable, expectingAlias, expectingCTE := false, false, false
	var lastTableKeyword, lastToken, statementVerb string
	runes := []rune(sql)

	for i := 0; i < len(runes); {
		remaining := string(runes[i:])
		char := runes[i]

		switch state {
		case stateNormal:
			if strings.HasPrefix(remaining, "--") {
				state = stateInSingleLineCommentDash
				i += 2
				continue
			}
			if strings.HasPrefix(remaining, "#") {
				state = stateInSingleLineCommentHash
				i++
				continue
			}
			if strings.HasPrefix(remaining, "/*") {
				state = stateInMultiLineComment
				i += 2
				continue
			}
			if char == ',' {
				if lastTableKeyword == "from" {
					expectingTable = true
					expectingAlias = false
				} else if statementVerb == "with" {
					expectingCTE = true
					expectingAlias = false
				}
				i++
				continue
			}
			if char == '(' {
				if expectingTable || expectingCTE || lastToken == "as" {
					consumed, err := parseSQL(string(runes[i+1:]), defaultProjectID, tableIDSet, visitedSQLs, aliases, true)
					if err != nil {
						return 0, err
					}
					i += consumed + 1
					if lastTableKeyword != "from" {
						expectingTable = false
					}
					expectingAlias = true
					expectingCTE = false
					continue
				}
			}
			if char == ')' {
				if inSubquery {
					return i + 1, nil
				}
			}
			if char == ';' {
				statementVerb = ""
				lastToken = ""
				expectingTable = false
				expectingAlias = false
				expectingCTE = false
				i++
				continue
			}
			remLow := strings.ToLower(remaining)
			if strings.HasPrefix(remLow, "r'''") {
				state = stateInRawTripleSingleQuoteString
				i += 4
				continue
			}
			if strings.HasPrefix(remLow, `r"""`) {
				state = stateInRawTripleDoubleQuoteString
				i += 4
				continue
			}
			if strings.HasPrefix(remLow, "r'") {
				state = stateInRawSingleQuoteString
				i += 2
				continue
			}
			if strings.HasPrefix(remLow, `r"`) {
				state = stateInRawDoubleQuoteString
				i += 2
				continue
			}
			if strings.HasPrefix(remaining, "'''") {
				state = stateInTripleSingleQuoteString
				i += 3
				continue
			}
			if strings.HasPrefix(remaining, `"""`) {
				state = stateInTripleDoubleQuoteString
				i += 3
				continue
			}
			if char == '\'' {
				state = stateInSingleQuoteString
				i++
				continue
			}
			if char == '"' {
				state = stateInDoubleQuoteString
				i++
				continue
			}

			if unicode.IsLetter(char) || char == '`' || char == '_' {
				parts, consumed, err := parseIdentifierSequence(remaining)
				if err != nil {
					return 0, err
				}
				if consumed == 0 {
					i++
					continue
				}
				keyword := strings.ToLower(parts[0])
				fullID := strings.ToLower(strings.Join(parts, "."))

				// Handle security-restricted operations and verb identification.
				if len(parts) == 1 {
					switch keyword {
					case "call":
						return 0, fmt.Errorf("CALL is not allowed when dataset restrictions are in place, as the called procedure's contents cannot be safely analyzed")
					case "immediate":
						if lastToken == "execute" {
							return 0, fmt.Errorf("EXECUTE IMMEDIATE is not allowed when dataset restrictions are in place, as its contents cannot be safely analyzed")
						}
					case "procedure", "function":
						if lastToken == "create" || lastToken == "create or replace" {
							return 0, fmt.Errorf("unanalyzable statements like '%s %s' are not allowed", strings.ToUpper(lastToken), strings.ToUpper(keyword))
						}
					case verbCreate, verbAlter, verbDrop, verbSelect, verbInsert, verbUpdate, verbDelete, verbMerge:
						if statementVerb == "" {
							statementVerb = keyword
						}
					}

					if statementVerb == verbCreate || statementVerb == verbAlter || statementVerb == verbDrop {
						if keyword == "schema" || keyword == "dataset" {
							return 0, fmt.Errorf("dataset-level operations like '%s %s' are not allowed when dataset restrictions are in place", strings.ToUpper(statementVerb), strings.ToUpper(keyword))
						}
					}
				}

				// Resolve aliases and identify table references.
				isKnownAlias := false
				if _, ok := aliases[fullID]; ok {
					isKnownAlias = true
				}
				if !isKnownAlias && len(parts) > 1 {
					if _, ok := aliases[strings.ToLower(parts[0])]; ok {
						isKnownAlias = true
					}
				}

				if expectingCTE {
					aliases[fullID] = struct{}{}
					aliases[strings.ToLower(parts[0])] = struct{}{}
					expectingCTE = false
				} else if expectingAlias {
					if len(parts) == 1 && (tableContextExitKeywords[keyword] || tableFollowsKeywords[keyword] || keyword == "select" || keyword == "with") {
						expectingAlias = false
					} else {
						aliases[fullID] = struct{}{}
						aliases[strings.ToLower(parts[0])] = struct{}{}
						expectingAlias = false
						isKnownAlias = true
					}
				}

				// Re-check aliases after potential registration.
				if !isKnownAlias {
					if _, ok := aliases[fullID]; ok {
						isKnownAlias = true
					}
				}

				if expectingTable && !isKnownAlias {
					if len(parts) >= 2 {
						tableID, err := formatTableID(parts, defaultProjectID)
						if err != nil {
							return 0, err
						}
						if tableID != "" {
							tableIDSet[tableID] = struct{}{}
						}
					}
					// For most keywords, we expect only one table.
					if lastTableKeyword != "from" {
						expectingTable = false
					}
					expectingAlias = true
				}

				// Update state machine based on the current keyword.
				if len(parts) == 1 {
					if keyword == "with" {
						expectingCTE = true
						statementVerb = "with"
					} else if keyword == "as" {
						if statementVerb != "with" {
							expectingAlias = true
						}
						expectingTable = false
					} else if _, ok := tableFollowsKeywords[keyword]; ok {
						expectingTable = true
						lastTableKeyword = keyword
						expectingAlias = false
					} else if _, ok := tableContextExitKeywords[keyword]; ok {
						expectingTable = false
						lastTableKeyword = ""
						expectingAlias = false
					}
					if lastToken == "create" && keyword == "or" {
						lastToken = "create or"
					} else if lastToken == "create or" && keyword == "replace" {
						lastToken = "create or replace"
					} else {
						lastToken = keyword
					}
				} else {
					lastToken = ""
				}
				i += consumed
				continue
			}
			i++
		case stateInSingleQuoteString:
			if char == '\\' {
				i += 2 // Skip backslash and the escaped character.
				continue
			}
			if char == '\'' {
				state = stateNormal
			}
			i++
		case stateInDoubleQuoteString:
			if char == '\\' {
				i += 2 // Skip backslash and the escaped character.
				continue
			}
			if char == '"' {
				state = stateNormal
			}
			i++
		case stateInTripleSingleQuoteString:
			if strings.HasPrefix(string(runes[i:]), "'''") {
				state = stateNormal
				i += 3
			} else {
				i++
			}
		case stateInTripleDoubleQuoteString:
			if strings.HasPrefix(string(runes[i:]), `"""`) {
				state = stateNormal
				i += 3
			} else {
				i++
			}
		case stateInSingleLineCommentDash, stateInSingleLineCommentHash:
			if char == '\n' {
				state = stateNormal
			}
			i++
		case stateInMultiLineComment:
			if strings.HasPrefix(string(runes[i:]), "*/") {
				state = stateNormal
				i += 2
			} else {
				i++
			}
		case stateInRawSingleQuoteString:
			if char == '\'' {
				state = stateNormal
			}
			i++
		case stateInRawDoubleQuoteString:
			if char == '"' {
				state = stateNormal
			}
			i++
		case stateInRawTripleSingleQuoteString:
			if strings.HasPrefix(string(runes[i:]), "'''") {
				state = stateNormal
				i += 3
			} else {
				i++
			}
		case stateInRawTripleDoubleQuoteString:
			if strings.HasPrefix(string(runes[i:]), `"""`) {
				state = stateNormal
				i += 3
			} else {
				i++
			}
		}
	}
	if inSubquery {
		return 0, fmt.Errorf("unclosed subquery parenthesis")
	}
	return len(runes), nil
}

// parseIdentifierSequence parses a sequence of dot-separated identifiers.
// It returns the parts of the identifier, the number of characters consumed, and an error.
func parseIdentifierSequence(s string) ([]string, int, error) {
	var parts []string
	var totalConsumed int
	runes := []rune(s)
	for {
		for totalConsumed < len(runes) && unicode.IsSpace(runes[totalConsumed]) {
			totalConsumed++
		}
		if totalConsumed >= len(runes) {
			break
		}

		var part string
		var consumed int

		if runes[totalConsumed] == '`' {
			end := strings.Index(string(runes[totalConsumed+1:]), "`")
			if end == -1 {
				return nil, 0, fmt.Errorf("unclosed backtick identifier")
			}
			part = string(runes[totalConsumed+1 : totalConsumed+end+1])
			consumed = end + 2
		} else if unicode.IsLetter(runes[totalConsumed]) || runes[totalConsumed] == '_' {
			end := totalConsumed
			for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsNumber(runes[end]) || runes[end] == '_' || runes[end] == '-') {
				end++
			}
			part = string(runes[totalConsumed:end])
			consumed = end - totalConsumed
		} else {
			break
		}

		parts = append(parts, strings.Split(part, ".")...)
		totalConsumed += consumed

		if totalConsumed >= len(runes) || runes[totalConsumed] != '.' {
			break
		}
		totalConsumed++
	}
	return parts, totalConsumed, nil
}

// IsAnyTableExplicitlyReferenced checks if any target tables are explicitly mentioned as
// identifiers in the SQL, correctly skipping comments and strings.
func IsAnyTableExplicitlyReferenced(sql, defaultProjectID string, targetTableIDs []string) (bool, error) {
	if len(targetTableIDs) == 0 {
		return false, nil
	}

	targets := make(map[string]struct{})
	for _, id := range targetTableIDs {
		targets[strings.ToLower(id)] = struct{}{}
	}

	state := stateNormal
	runes := []rune(sql)

	for i := 0; i < len(runes); {
		remaining := string(runes[i:])
		char := runes[i]

		switch state {
		case stateNormal:
			if strings.HasPrefix(remaining, "--") {
				state = stateInSingleLineCommentDash
				i += 2
				continue
			}
			if strings.HasPrefix(remaining, "#") {
				state = stateInSingleLineCommentHash
				i++
				continue
			}
			if strings.HasPrefix(remaining, "/*") {
				state = stateInMultiLineComment
				i += 2
				continue
			}

			if unicode.IsLetter(char) || char == '`' || char == '_' {
				parts, consumed, err := parseIdentifierSequence(remaining)
				if err != nil {
					return false, err
				}
				if consumed > 0 {
					if len(parts) < 2 {
						i += consumed
						continue
					}
					fullID := strings.ToLower(strings.Join(parts, "."))
					for target := range targets {
						// Match exact table name or as a prefix for column references.
						if fullID == target || strings.HasPrefix(fullID, target+".") {
							return true, nil
						}
						// Also try matching with the default project ID prefix.
						if defaultProjectID != "" {
							withDefault := strings.ToLower(defaultProjectID + "." + fullID)
							if withDefault == target || strings.HasPrefix(withDefault, target+".") {
								return true, nil
							}
						}
					}
					i += consumed
					continue
				}
			}

			// Handle various BigQuery string literal formats.
			remLow := strings.ToLower(remaining)
			if strings.HasPrefix(remLow, "r'''") {
				state = stateInRawTripleSingleQuoteString
				i += 4
				continue
			}
			if strings.HasPrefix(remLow, `r"""`) {
				state = stateInRawTripleDoubleQuoteString
				i += 4
				continue
			}
			if strings.HasPrefix(remLow, "r'") {
				state = stateInRawSingleQuoteString
				i += 2
				continue
			}
			if strings.HasPrefix(remLow, `r"`) {
				state = stateInRawDoubleQuoteString
				i += 2
				continue
			}
			if strings.HasPrefix(remaining, "'''") {
				state = stateInTripleSingleQuoteString
				i += 3
				continue
			}
			if strings.HasPrefix(remaining, `"""`) {
				state = stateInTripleDoubleQuoteString
				i += 3
				continue
			}
			if char == '\'' {
				state = stateInSingleQuoteString
				i++
				continue
			}
			if char == '"' {
				state = stateInDoubleQuoteString
				i++
				continue
			}

		case stateInSingleQuoteString:
			if char == '\\' {
				i += 2
				continue
			}
			if char == '\'' {
				state = stateNormal
			}
		case stateInDoubleQuoteString:
			if char == '\\' {
				i += 2
				continue
			}
			if char == '"' {
				state = stateNormal
			}
		case stateInTripleSingleQuoteString:
			if strings.HasPrefix(remaining, "'''") {
				state = stateNormal
				i += 3
				continue
			}
		case stateInTripleDoubleQuoteString:
			if strings.HasPrefix(remaining, `"""`) {
				state = stateNormal
				i += 3
				continue
			}
		case stateInSingleLineCommentDash, stateInSingleLineCommentHash:
			if char == '\n' {
				state = stateNormal
			}
		case stateInMultiLineComment:
			if strings.HasPrefix(remaining, "*/") {
				state = stateNormal
				i += 2
				continue
			}
		case stateInRawSingleQuoteString:
			if char == '\'' {
				state = stateNormal
			}
		case stateInRawDoubleQuoteString:
			if char == '"' {
				state = stateNormal
			}
		case stateInRawTripleSingleQuoteString:
			if strings.HasPrefix(remaining, "'''") {
				state = stateNormal
				i += 3
				continue
			}
		case stateInRawTripleDoubleQuoteString:
			if strings.HasPrefix(remaining, `"""`) {
				state = stateNormal
				i += 3
				continue
			}
		}
		i++
	}

	return false, nil
}

func formatTableID(parts []string, defaultProjectID string) (string, error) {
	if len(parts) < 2 || len(parts) > 3 {
		// Not a table identifier (could be a CTE, column, etc.).
		return "", nil
	}

	if len(parts) == 3 { // project.dataset.table
		return strings.Join(parts, "."), nil
	}

	// dataset.table
	if defaultProjectID == "" {
		return "", fmt.Errorf("query contains table '%s' without project ID, and no default project ID is provided", strings.Join(parts, "."))
	}
	return fmt.Sprintf("%s.%s", defaultProjectID, strings.Join(parts, ".")), nil
}
