package rack_test

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"os"

	"github.com/convox/praxis/provider/local"
	"github.com/convox/praxis/sdk/rack"
	"github.com/convox/praxis/server"
	"github.com/convox/praxis/server/controllers"
)

var ts *httptest.Server

const tmpDir = "/tmp/convox"

func setup() (rack.Rack, error) {
	tmp, err := ioutil.TempDir("", "praxis")
	if err != nil {
		return nil, err
	}

	fmt.Printf("tmp = %+v\n", tmp)

	p := &local.Provider{
		Frontend: "none",
		Root:     tmp,
		Test:     true,
	}

	if err := p.Init(); err != nil {
		return nil, err
	}

	controllers.Provider = p

	ts = httptest.NewUnstartedServer(server.New())
	ts.TLS = &tls.Config{
		NextProtos: []string{"h2"},
	}

	ts.StartTLS()

	return rack.New(ts.URL)
}

func cleanup() {
	ts.Close()
	os.RemoveAll(tmpDir)
}
