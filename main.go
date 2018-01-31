package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/pkg/errors"
)

type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

func (pd *policyDocument) AddStatement(statement policyStatement) error {
	found := false
	for _, element := range pd.Statement {
		if element.Principal.AWS == statement.Principal.AWS {
			return fmt.Errorf("arn (%s) already trusted by role (%s)", awsARN, roleName)
		}
	}
	if !found {
		pd.Statement = append(pd.Statement, statement)
	}

	return nil
}

type policyStatement struct {
	Action    string          `json:"Action"`
	Effect    string          `json:"Effect"`
	Principal policyPrincipal `json:"Principal"`
}

type policyPrincipal struct {
	Service string `json:"Service,omitempty"`
	AWS     string `json:"AWS,omitempty"`
}

var (
	awsARN   string
	roleName string
)

func main() {

	flag.StringVar(&awsARN, "arn", "", "ARN Being Added")
	flag.StringVar(&roleName, "role-name", "", "Role Name To Edit")

	flag.Parse()

	if awsARN == "" || roleName == "" {
		fmt.Println("-arn and -role-name are required.")
		return
	}

	// create the service
	svc := iam.New(session.New())

	// fetch the document
	document, err := getExistingPolicyDocument(svc)
	if err != nil {
		panic(err.Error())
	}

	// add the arn to the document
	err = addARNToDocument(document)
	if err != nil {
		panic(err.Error())
	}

	// update the document this will only be hit if the arn doesn't exist in the current document
	err = updatePolicyDocument(svc, document)
	if err != nil {
		panic(err.Error())
	}
}

func addARNToDocument(document policyDocument) error {
	// try and add it to the role
	err := document.AddStatement(
		policyStatement{
			Effect: "Allow",
			Action: "sts:AssumeRole",
			Principal: policyPrincipal{
				AWS: awsARN,
			},
		},
	)

	return errors.Wrap(err, "Adding ARN to document")
}

func updatePolicyDocument(svc *iam.IAM, document policyDocument) error {
	// convert the document back into json
	updatedDocument, err := json.Marshal(document)
	if err != nil {
		return errors.Wrap(err, "Converting Document into JSON")
	}

	// create the update assume role policy input
	input1 := &iam.UpdateAssumeRolePolicyInput{
		PolicyDocument: aws.String(string(updatedDocument)),
		RoleName:       aws.String(roleName),
	}

	// update the role
	_, err = svc.UpdateAssumeRolePolicy(input1)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				return errors.Wrap(aerr, iam.ErrCodeNoSuchEntityException)
			case iam.ErrCodeMalformedPolicyDocumentException:
				return errors.Wrap(aerr, iam.ErrCodeMalformedPolicyDocumentException)
			case iam.ErrCodeLimitExceededException:
				return errors.Wrap(aerr, iam.ErrCodeLimitExceededException)
			case iam.ErrCodeUnmodifiableEntityException:
				return errors.Wrap(aerr, iam.ErrCodeUnmodifiableEntityException)
			case iam.ErrCodeServiceFailureException:
				return errors.Wrap(aerr, iam.ErrCodeServiceFailureException)
			default:
				errors.Wrap(aerr, "Unknown AWS Error")
			}
		}
	}

	return nil
}

func getExistingPolicyDocument(svc *iam.IAM) (policyDocument, error) {
	var document policyDocument
	input := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}

	result, err := svc.GetRole(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				return document, errors.Wrap(aerr, iam.ErrCodeNoSuchEntityException)
			case iam.ErrCodeServiceFailureException:
				return document, errors.Wrap(aerr, iam.ErrCodeServiceFailureException)
			default:
				return document, errors.Wrap(aerr, "Unknown AWS Error")
			}
		}
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		return document, errors.Wrap(err, "Generic Error")
	}

	// get the role policy document from the result
	rawValue := aws.StringValue(result.Role.AssumeRolePolicyDocument)
	// clean it up
	str, err := url.QueryUnescape(rawValue)
	if err != nil {
		return document, errors.Wrap(err, "Query Unescape Error")
	}

	// create the golang version of it
	err = json.Unmarshal([]byte(str), &document)

	return document, errors.Wrap(err, "Converting Json to Struct")
}
