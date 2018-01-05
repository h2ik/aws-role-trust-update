# AWS Role Trust Update

A quick utility for updating AWS IAM role trust policies to allow other roles to assume this policy

```console
aws-role-trust-update -role-name <rolename here> -arn <awn arn here>
```

## Help

Make sure that the aws cli tool has been installed and has been configured.  If not you can use the following environment variables:

- AWS_ACCESS_KEY
- AWS_SECRET_KEY

### Existing Role ARN

To get an existing roles ARN you can do the following with the AWS cli

```console
aws iam get-role --role-name <another role that is attached to an ec2 instance> | grep "Arn" | awk '{ print substr($2,2,length($2)-2) }'
```
