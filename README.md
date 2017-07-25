## Failed Experiment
Please note this was a bit of experimentation but it didn't work as too many of the methods required in the native AWS terraform provider were not public.

## Usage
Use this just as you would the native AWS provider (https://www.terraform.io/docs/providers/aws/) but there are additional configuration values to wrap the native AWS provider with federated authentication:

```
# Configure the AWS Wrapper Provider
provider "awswrapper" {
    UserId = "userid-to-authenticate-to-auth-web-service"
    Password = "password-to-authenticate-to-auth-web-service"
    AuthEndPoint = "https://auth-web-service-endpoint/creds-url"
    TrustCA = "/path/to/CA.pem"
    RoleId = "auth-web-service-role-reference"
}
```
All the other configuration options for the native AWS provider can be used with only a few exceptions.

The follow configurations from the native AWS provider are overridden so will not function:
* access_key
* secret_key
* token