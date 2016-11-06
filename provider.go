package main

import (
	"errors"
	"fmt"
	"github.com/hashicorp/terraform/builtin/providers/aws"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/jcmturner/aws-cli-wrapper/authenticate"
	cfg "github.com/jcmturner/aws-cli-wrapper/config"
	"log"
	"os/user"
)

func Provider() terraform.ResourceProvider {
	// Use the native terraform provider
	p := aws.Provider().(*schema.Provider)
	// Add the new configuration value to the schema
	usr, _ := user.Current()
	p.Schema["UserId"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    false,
		Default:     usr.Username,
		Description: "Your username",
	}
	p.Schema["Password"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    true,
		Default:     "",
		Description: "Your password",
	}
	p.Schema["AuthEndPoint"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    false,
		Default:     "",
		Description: "The URL of the federation authentication service",
	}
	p.Schema["TrustCA"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    false,
		Default:     "",
		Description: "The path to the signing CA certificate (PEM format) for the authentication service",
	}
	p.Schema["RoleId"] = &schema.Schema{
		Type:        schema.TypeString,
		Optional:    false,
		Default:     "",
		Description: "The reference ID to the IAM role that will be assumed",
	}
	// Replace the ConfigureFunc to talk to the auth service
	p.ConfigureFunc = providerConfigure
	return p
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	log.Print("[INFO] Authenticating to federation service")
	accessKey, secretKey, sessionKey, err := federationAuthenticate(
		d.Get("UserId").(string),
		d.Get("Password").(string),
		d.Get("AuthEndPoint").(string),
		d.Get("TrustCA").(string),
		d.Get("RoleId").(string),
	)
	if err != nil {
		return nil, err
	}
	log.Print("[INFO] Authentication to federation service successful")
	err = d.Set("access_key", accessKey)
	if err != nil {
		return nil, err
	}
	err = d.Set("secret_key", secretKey)
	if err != nil {
		return nil, err
	}
	err = d.Set("token", sessionKey)
	if err != nil {
		return nil, err
	}

	// The rest of this function is copied unchanged from https://github.com/hashicorp/terraform/blob/master/builtin/providers/aws/provider.go
	// The function providerConfigure is not made public so it cannot be called directly
	config := aws.Config{
		AccessKey:               d.Get("access_key").(string),
		SecretKey:               d.Get("secret_key").(string),
		Profile:                 d.Get("profile").(string),
		CredsFilename:           d.Get("shared_credentials_file").(string),
		Token:                   d.Get("token").(string),
		Region:                  d.Get("region").(string),
		MaxRetries:              d.Get("max_retries").(int),
		DynamoDBEndpoint:        d.Get("dynamodb_endpoint").(string),
		KinesisEndpoint:         d.Get("kinesis_endpoint").(string),
		Insecure:                d.Get("insecure").(bool),
		SkipCredsValidation:     d.Get("skip_credentials_validation").(bool),
		SkipRequestingAccountId: d.Get("skip_requesting_account_id").(bool),
		SkipMetadataApiCheck:    d.Get("skip_metadata_api_check").(bool),
		S3ForcePathStyle:        d.Get("s3_force_path_style").(bool),
	}

	assumeRoleList := d.Get("assume_role").(*schema.Set).List()
	if len(assumeRoleList) == 1 {
		assumeRole := assumeRoleList[0].(map[string]interface{})
		config.AssumeRoleARN = assumeRole["role_arn"].(string)
		config.AssumeRoleSessionName = assumeRole["session_name"].(string)
		config.AssumeRoleExternalID = assumeRole["external_id"].(string)
		log.Printf("[INFO] assume_role configuration set: (ARN: %q, SessionID: %q, ExternalID: %q)",
			config.AssumeRoleARN, config.AssumeRoleSessionName, config.AssumeRoleExternalID)
	} else {
		log.Print("[INFO] No assume_role block read from configuration")
	}

	endpointsSet := d.Get("endpoints").(*schema.Set)

	for _, endpointsSetI := range endpointsSet.List() {
		endpoints := endpointsSetI.(map[string]interface{})
		config.IamEndpoint = endpoints["iam"].(string)
		config.Ec2Endpoint = endpoints["ec2"].(string)
		config.ElbEndpoint = endpoints["elb"].(string)
		config.S3Endpoint = endpoints["s3"].(string)
	}

	if v, ok := d.GetOk("allowed_account_ids"); ok {
		config.AllowedAccountIds = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("forbidden_account_ids"); ok {
		config.ForbiddenAccountIds = v.(*schema.Set).List()
	}

	return config.Client()
}

func federationAuthenticate(userId, passwd, roleId, ep, trustCert string) (accessKey, secretKey, sessionKey string, err error) {
	c := cfg.NewConfig()
	c.ReSTClientConfig.WithEndPoint(ep).WithUserId(userId).WithPassword(passwd).WithCAFilePath(trustCert)
	c.WithRoleId(roleId)

	var a authenticate.Authenticate
	err = a.NewRequest(c)
	if err != nil {
		err = errors.New(fmt.Sprintf("Could not prepare authentication request to federation service: %v\n", err))
		return
	}
	err = a.Process()
	if err != nil {
		err = errors.New(fmt.Sprintf("Failed to authenticate to federation service: %v\n", err))
		return
	}
	accessKey = a.Credentials.AccessKeyID
	secretKey = a.Credentials.SecretAccessKey
	sessionKey = a.Credentials.SessionToken
	return
}
