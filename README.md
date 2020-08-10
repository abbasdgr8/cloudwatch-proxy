# AWS CloudWatch Proxy 

Logging adapter that consumes log streams from AWS CloudWatch, streams them to other log destinations. Also capable of identifying alerts and notifying via Slack and Email

This has been developed as a Serverless application. This repository is featured as an application on the official Serverless example docs.

## Pre-Requisites
- You must have Python 2.7.1 installed and setup on your machine
- You must have an AWS Account and access keys must be setup under the default profile within ~/.aws/credentials
- You must have Serverless 1.27.2 installed and setup on your machine - https://serverless.com/framework/docs/providers/aws/guide/installation/


## Deploy
In order to deploy, change your present working directory to the project directory and then simply run

```bash
serverless deploy
```
