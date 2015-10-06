package interceptor

import (
	"fmt"
	"os/exec"
	"strings"
	"unicode"
)

func (cf *config) chainRule() []interface{} {
	return []interface{}{"-i", cf.bridge, "-j", cf.chain}
}

type ipTablesError struct {
	cmd    string
	output string
}

func (err ipTablesError) Error() string {
	return fmt.Sprintf("'iptables %s' gave error: ", err.cmd, err.output)
}

func flatten(args []interface{}, onto []string) []string {
	for _, arg := range args {
		switch argt := arg.(type) {
		case []interface{}:
			onto = flatten(argt, onto)
		default:
			onto = append(onto, fmt.Sprint(arg))
		}
	}
	return onto
}

func doIPTables(args ...interface{}) error {
	flatArgs := flatten(args, nil)
	output, err := exec.Command("iptables", flatArgs...).CombinedOutput()
	switch errt := err.(type) {
	case nil:
	case *exec.ExitError:
		if !errt.Success() {
			// sanitize iptables output
			limit := 200
			sanOut := strings.Map(func(ch rune) rune {
				if limit == 0 {
					return -1
				}
				limit--

				if unicode.IsControl(ch) {
					ch = ' '
				}
				return ch
			}, string(output))
			return ipTablesError{
				cmd:    strings.Join(flatArgs, " "),
				output: sanOut,
			}
		}
	default:
		return err
	}

	return nil
}

func (cf *config) setupChain() error {
	err := cf.deleteChain()
	if err != nil {
		return err
	}

	err = doIPTables("-t", "nat", "-N", cf.chain)
	if err != nil {
		return err
	}

	return doIPTables("-t", "nat", "-A", "PREROUTING", cf.chainRule())
}

func (cf *config) deleteChain() error {
	// First, remove any rules in the chain
	err := doIPTables("-t", "nat", "-F", cf.chain)
	if err != nil {
		if _, ok := err.(ipTablesError); ok {
			// this probably means the chain doesn't exist
			return nil
		}
	}

	// Remove the rule that references our chain from PREROUTING,
	// if it's there.
	for {
		err := doIPTables("-t", "nat", "-D", "PREROUTING",
			cf.chainRule())
		if err != nil {
			if _, ok := err.(ipTablesError); !ok {
				return err
			}

			// a "no such rule" error
			break
		}
	}

	// Actually delete the chain at last
	return doIPTables("-t", "nat", "-X", cf.chain)
}

func (cf *config) addRule(args []interface{}) error {
	return cf.frobRule("-A", args)
}

func (cf *config) deleteRule(args []interface{}) error {
	return cf.frobRule("-D", args)
}

func (cf *config) frobRule(op string, args []interface{}) error {
	return doIPTables("-t", "nat", op, cf.chain, args)
}
