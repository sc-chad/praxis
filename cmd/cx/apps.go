package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/convox/praxis/sdk/rack"
	"github.com/convox/praxis/stdcli"
	cli "gopkg.in/urfave/cli.v1"
)

func init() {
	flags := []cli.Flag{
		cli.BoolFlag{
			Name:  "force",
			Usage: "delete without verification prompt",
		},
	}

	stdcli.RegisterCommand(cli.Command{
		Name:        "apps",
		Description: "list applications",
		Action:      runApps,
		Flags:       globalFlags,
		Subcommands: cli.Commands{
			cli.Command{
				Name:        "create",
				Description: "create an application",
				Usage:       "<name>",
				Action:      runAppsCreate,
				Flags:       globalFlags,
			},
			cli.Command{
				Name:        "delete",
				Aliases:     []string{"rm"},
				Description: "delete an application",
				Usage:       "<name>",
				Action:      runAppsDelete,
				Flags:       append(flags, globalFlags...),
			},
			cli.Command{
				Name:        "info",
				Description: "get application info",
				Usage:       "[name]",
				Action:      runAppsInfo,
				Flags:       globalFlags,
			},
		},
	})
}

func runApps(c *cli.Context) error {
	apps, err := Rack(c).AppList()
	if err != nil {
		return stdcli.Error(err)
	}

	t := stdcli.NewTable("NAME", "STATUS")

	for _, app := range apps {
		t.AddRow(app.Name, app.Status)
	}

	t.Print()

	return nil
}

func runAppsCreate(c *cli.Context) error {
	name, err := appName(c, ".")
	if err != nil {
		return stdcli.Error(err)
	}

	if len(c.Args()) > 0 {
		name = c.Args()[0]
	}

	stdcli.Startf("creating <name>%s</name>", name)

	if _, err = Rack(c).AppCreate(name); err != nil {
		return stdcli.Error(err)
	}

	if err := tickWithTimeout(2*time.Second, 1*time.Minute, notAppStatus(Rack(c), name, "creating")); err != nil {
		return err
	}

	stdcli.OK()

	return nil
}

func runAppsDelete(c *cli.Context) error {
	if len(c.Args()) != 1 {
		return stdcli.Usage(c)
	}

	name := c.Args()[0]
	app := name

	if !c.Bool("force") {
		if terminal.IsTerminal(int(os.Stdin.Fd())) {
			rack, err := currentRack(c)
			if err != nil {
				return stdcli.Error(err)
			}

			name = fmt.Sprintf("%s/%s", rack, name)

			stdcli.Writef("Are you sure? Type <bad>%s</bad> to confirm:\n", name)
			stdcli.Writef("> ")

			input := bufio.NewReader(os.Stdin)

			confirm, err := input.ReadString('\n')
			if err != nil {
				return stdcli.Error(err)
			}

			if strings.TrimSpace(confirm) != name {
				return stdcli.Errorf("Aborting deletion.")
			}
		} else {
			return stdcli.Errorf("Use the --force flag for a non-interactive session.")
		}
	}

	stdcli.Startf("deleting <name>%s</name>", name)

	if err := Rack(c).AppDelete(app); err != nil {
		return stdcli.Error(err)
	}

	stdcli.OK()

	return nil
}

func runAppsInfo(c *cli.Context) error {
	app, err := appName(c, ".")
	if err != nil {
		return stdcli.Error(err)
	}

	if len(c.Args()) > 0 {
		app = c.Args()[0]
	}

	a, err := Rack(c).AppGet(app)
	if err != nil {
		return stdcli.Error(err)
	}

	info := stdcli.NewInfo()

	info.Add("Name", a.Name)
	info.Add("Release", a.Release)
	info.Add("Status", a.Status)

	info.Print()

	return nil
}

func isAppStatus(r rack.Rack, app, status string) func() (bool, error) {
	return func() (bool, error) {
		app, err := r.AppGet(app)
		if err != nil {
			return true, err
		}
		if app.Status == status {
			return true, nil
		}

		return false, nil
	}
}

func notAppStatus(r rack.Rack, app, status string) func() (bool, error) {
	return func() (bool, error) {
		app, err := r.AppGet(app)
		if err != nil {
			return true, err
		}
		if app.Status != status {
			return true, nil
		}

		return false, nil
	}
}
