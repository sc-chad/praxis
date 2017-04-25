package aws

import (
	"fmt"
	"io/ioutil"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/convox/praxis/types"
	"github.com/fatih/color"
)

func (p *Provider) SystemGet() (*types.System, error) {
	domain, err := p.rackOutput("Domain")
	if err != nil {
		return nil, err
	}

	system := &types.System{
		Domain:  domain,
		Name:    p.Name,
		Image:   fmt.Sprintf("convox/praxis:%s", p.Version),
		Version: p.Version,
	}

	return system, nil
}

func (p *Provider) SystemInstall(name string, opts types.SystemInstallOptions) (string, error) {
	version := coalesce(opts.Version, "latest")
	template := fmt.Sprintf("https://s3.amazonaws.com/praxis-releases/release/%s/formation/rack.json", version)

	_, err := p.CloudFormation().CreateStack(&cloudformation.CreateStackInput{
		Capabilities: []*string{aws.String("CAPABILITY_IAM")},
		Parameters: []*cloudformation.Parameter{
			&cloudformation.Parameter{ParameterKey: aws.String("Password"), ParameterValue: aws.String(opts.Password)},
			&cloudformation.Parameter{ParameterKey: aws.String("Version"), ParameterValue: aws.String(version)},
		},
		StackName: aws.String(name),
		Tags: []*cloudformation.Tag{
			{Key: aws.String("Name"), Value: aws.String(name)},
			{Key: aws.String("System"), Value: aws.String("convox")},
			{Key: aws.String("Type"), Value: aws.String("rack")},
			{Key: aws.String("Version"), Value: aws.String(version)},
		},
		TemplateURL: aws.String(template),
	})
	if err != nil {
		return "", err
	}

	if err := p.cloudformationProgress(name, opts); err != nil {
		return "", err
	}

	sres, err := p.CloudFormation().DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(name),
	})
	if err != nil || len(sres.Stacks) < 1 || *sres.Stacks[0].StackStatus == "ROLLBACK_COMPLETE" {
		return "", fmt.Errorf("installation failed")
	}

	return p.stackOutput(name, "Endpoint")
}

func (p *Provider) SystemUninstall(name string, opts types.SystemInstallOptions) error {
	_, err := p.CloudFormation().DeleteStack(&cloudformation.DeleteStackInput{
		StackName: aws.String(name),
	})
	if err != nil {
		return err
	}

	if err := p.cloudformationProgress(name, opts); err != nil {
		return err
	}

	return nil
}

func (p *Provider) SystemUpdate(version string, opts types.SystemUpdateOptions) error {
	return fmt.Errorf("unimplemented")
}

func (p *Provider) cloudformationProgress(name string, opts types.SystemInstallOptions) error {
	w := opts.Output
	if w == nil {
		w = ioutil.Discard
	}

	events := map[string]cloudformation.StackEvent{}

	for {
		eres, err := p.CloudFormation().DescribeStackEvents(&cloudformation.DescribeStackEventsInput{
			StackName: aws.String(name),
		})
		if err != nil {
			return nil // stack is gone, we're done
		}

		sort.Slice(eres.StackEvents, func(i, j int) bool { return eres.StackEvents[i].Timestamp.Before(*eres.StackEvents[j].Timestamp) })

		for _, e := range eres.StackEvents {
			if _, ok := events[*e.EventId]; !ok {
				line := fmt.Sprintf("%-20s  %-28s  %s", *e.ResourceStatus, *e.LogicalResourceId, *e.ResourceType)

				if !opts.Color {
					fmt.Fprintf(w, "%s\n", line)
				} else {
					switch *e.ResourceStatus {
					case "CREATE_IN_PROGRESS":
						fmt.Fprintf(w, "%s\n", color.YellowString(line))
					case "CREATE_COMPLETE":
						fmt.Fprintf(w, "%s\n", color.GreenString(line))
					case "CREATE_FAILED":
						fmt.Fprintf(w, "%s\n  ERROR: %s\n", color.RedString(line), *e.ResourceStatusReason)
					case "DELETE_IN_PROGRESS", "DELETE_COMPLETE", "ROLLBACK_IN_PROGRESS", "ROLLBACK_COMPLETE":
						fmt.Fprintf(w, "%s\n", color.RedString(line))
					default:
						fmt.Fprintf(w, "%s\n", line)
					}
				}

				events[*e.EventId] = *e
			}
		}

		sres, err := p.CloudFormation().DescribeStacks(&cloudformation.DescribeStacksInput{
			StackName: aws.String(name),
		})
		if err != nil {
			return nil // stack is gone, we're done
		}

		if sres == nil || len(sres.Stacks) < 1 {
			return fmt.Errorf("could not find stack: %s", name)
		}

		switch *sres.Stacks[0].StackStatus {
		case "CREATE_COMPLETE":
			return nil
		case "ROLLBACK_COMPLETE":
			return fmt.Errorf("installation failed")
		}

		time.Sleep(2 * time.Second)
	}
}
