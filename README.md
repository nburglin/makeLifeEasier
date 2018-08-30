## Description

This is a Go program designed create a program that uses APIs to allow users to hit an API to execute remote commands
on a server. 
This allows a user to create a config file that can be executed multiple times to avoid requiring users to ssh
to the remote server to execute the commands. It ultimately helps automate and speed up processes.

## Configuration

The program sets up APIs that will wait for a user to hit them. 
It expects there to be a 'conf' directory in which the config files live.
It requires a POST command to actually execute a config file detailed below.

##Create Executable

It's expected that you have GO installed locally. You can execute the command below to retrieve the source

```bash
go get github.com/nburglin/makeLifeEasier
```

This will put the executable in your $GOPATH/bin, however you must first make sure you build an executable that will be able to run
on your remote server. For instance, if you are going to be running on a linux host with AMD, your build command will look like this:

```bash
env GOOS=linux GOARCH=amd64 go install github.com/nburglin/makeLifeEasier
```

In the example above, the executable you need will be found in $GOPATH/bin/linux_amd64/makeLifeEasier


## Available APIs

/ (GET)
 * Displays basic info

/configs (GET)
 * Displays list of all available configs that are possible to run
 
 /configs/{configname} (POST)
  * Executes the config playbook
  
  
 ## Config Options
 Config playbooks currently must be in json format
 
 json objects in the playbook:
 
  * PrivateKeyDir \* 
      * The directory in which the private key to use is located
  * PrivateKeyFile \* 
      * The filename of the private key to be used to connect to the remote server
  * Host \* 
      * The hostname of the remote server. Can be hostname or IP
  * Port 
      * Port number to connect on
  * User
      * Username of account to ssh to the remote server with and execute commands as
      * Default is ec2-user
  * Commands
      * A list of commands to execute on the remote server
  * Script
      * Full path to script to execute on the remote server
  * RemoteScriptPath
      * Location on the remote server where the script is copied to
      * Default to /var/tmp/
  * DeleteOnDisconnect
      * Delete the script copied to the remote server. Set to false to help troubleshooting.
      * Default to true
  * Region
      * Region of AWS account for AWS secrets
      * Default to us-east-1
      
## Requirements

The application requires there to be a .aws/credentials file with AWS API key info for the user running the app.

The application listens on port 8000 for the REST calls

## To-Do
Lots...

 * Need to add permissions/roles so that only specific users can execute the config playbooks
 * Configure it so that AWS Secrets does not have to be used for the password store. Maybe allow basic username/password
 * Right now if both script and commands are present in the playbook, script always runs first. Allow the user to choose
 * Allow multiple scripts instead of single script
 * Create a PUT API that allows users to update playbooks
 * Create a GET API that downloads the logs
 * Accept voice commands (ie from Google/Alexa)
 * Make PrivateKeyDir default to a location similar to conf directory
 * Add option to submit the Hostname in the POST so the user can re-use the same playbook across multiple hosts
 * Don't fatally crash on execution failures (ie failure to authenticate with remote host, etc...)
 * Load .bash_profile of user on login. 