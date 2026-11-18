package winrm

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

const outputWriterResponse = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:ReceiveResponse>
<rsp:Stream Name="stdout">Zmlyc3Q=</rsp:Stream>
<rsp:Stream Name="stderr">ZXJyb3I=</rsp:Stream>
<rsp:Stream Name="stdout">bGFzdA==</rsp:Stream>
<rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>123</rsp:ExitCode></rsp:CommandState>
</rsp:ReceiveResponse></s:Body></s:Envelope>`

type outputFailureWriter struct {
	err   error
	calls int
}

func (w *outputFailureWriter) Write(p []byte) (int, error) {
	w.calls++
	return len(p) - 1, w.err
}

func TestOutputWriterErrors(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		for _, single := range []bool{false, true} {
			name := stream
			if single {
				name += "/single"
			} else {
				name += "/combined"
			}
			t.Run(name, func(t *testing.T) {
				parse := func(w io.Writer) (bool, int, error) {
					if single {
						return ParseSlurpOutputResponse(outputWriterResponse, w, stream)
					}
					if stream == "stdout" {
						return ParseSlurpOutputErrResponse(outputWriterResponse, w, io.Discard)
					}
					return ParseSlurpOutputErrResponse(outputWriterResponse, io.Discard, w)
				}
				sentinel := errors.New("output destination failed")
				for _, writeErr := range []error{sentinel, nil} {
					w := &outputFailureWriter{err: writeErr}
					_, _, err := parse(w)
					want := writeErr
					if want == nil {
						want = io.ErrShortWrite
					}
					if !errors.Is(err, want) {
						t.Errorf("write error = %v, want %v", err, want)
					}
					if w.calls != 1 {
						t.Errorf("writer called %d times after failure, want 1", w.calls)
					}
				}

				f, err := os.CreateTemp(t.TempDir(), "output")
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				if _, _, err := parse(f); !errors.Is(err, os.ErrClosed) {
					t.Errorf("closed output file: got %v, want os.ErrClosed", err)
				}

				var out bytes.Buffer
				finished, code, err := parse(&out)
				want := "firstlast"
				if stream == "stderr" {
					want = "error"
				}
				if err != nil || !finished || code != 123 || out.String() != want {
					t.Fatalf("successful output = (%v, %d, %v, %q), want (true, 123, nil, %q)", finished, code, err, out.String(), want)
				}
			})
		}
	}
}
