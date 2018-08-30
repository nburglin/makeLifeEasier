package dao

import (
    "golang.org/x/crypto/ssh"
    "io/ioutil"
    "log"
    "path/filepath"
    "github.com/spf13/viper"
    "io"
    "github.com/tmc/scp"
    "bufio"
    "strings"
    "time"
    "os"
    "github.com/aws/aws-sdk-go/service/secretsmanager"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/aws"
    "encoding/json"
)

type AppConfig struct {
    PrivateKeyDir string
    PrivateKeyFile string
    Host string
    Port string
    User string
    Commands []string
    Script string
    RemoteScriptPath string
    DeleteOnDisconnect bool
    Region string
}

type DefaultPageReturn struct {
    Message string `json:"message,omitempty"`
}

type AvailableConfigsJSON struct {
    Count int `json: "count"`
    Message string `json: "message,omitempty"`
    Files []string `json: "files"`
}

//Error Handler function
func ErrorChecker(message string, err error) {
    if err != nil {
        log.Fatalf("FATAL - %v Error: %v", message, err)
    }
}

//Read in config file
func ReadConfigs (configFile string, configPath string) AppConfig  {
    log.Println("Reading in Configs")
    var appConf AppConfig
    viper.SetConfigName(configFile)
    viper.AddConfigPath(configPath)
    viper.SetDefault("User", "ec2-user")
    viper.SetDefault("RemoteScriptPath", "/var/tmp/")
    viper.SetDefault("DeleteOnDisconnect", "true")
    viper.SetDefault("Region", "us-east-1")
    err := viper.ReadInConfig()
    ErrorChecker("Error reading the config file.", err)

    //debug
    Type := viper.GetString("Payload.type")
    log.Println(Type)

    log.Printf("Config file successfully loaded from: %s\n", viper.ConfigFileUsed())

    //Set config file values into the AppConfig struct
    err = viper.Unmarshal(&appConf)
    log.Printf("%+v", appConf)
    ErrorChecker("Unable to decode config into the struct.", err)

    return appConf

}


//Use certificates to connect to the server
func PublicKeyFile (dir string, file string) ssh.AuthMethod {
    //use Clean to ensure there is not a trailing slash on the directory var prior to concatenating it
    dir = filepath.Clean(dir)
    file = dir + "/" + file
    buffer, err := ioutil.ReadFile(file)
    ErrorChecker("Unknown Error", err)

    key, err := ssh.ParsePrivateKey(buffer)
    ErrorChecker("Unknown Error", err)


    return ssh.PublicKeys(key)
}

//Create an ssh Client with correct configuration
func SshConfig (appConf AppConfig) *ssh.ClientConfig {
    sshConfig := &ssh.ClientConfig{
        User: appConf.User,
        Auth: []ssh.AuthMethod{
            PublicKeyFile(appConf.PrivateKeyDir, appConf.PrivateKeyFile)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey()}
    return sshConfig
}

func CreateSshConnection (appConf AppConfig) *ssh.Session {
    //Create the sshconfig
    sshConfig := &ssh.ClientConfig{
        User: appConf.User,
        Auth: []ssh.AuthMethod{
            PublicKeyFile(appConf.PrivateKeyDir, appConf.PrivateKeyFile)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey()}

    host := appConf.Host + ":" + appConf.Port
    connection, err := ssh.Dial("tcp", host, sshConfig)
    ErrorChecker("Unknown Error creating connection to host.", err)

    //create new session
    session, err := connection.NewSession()
    if err != nil {
        panic(err)
    }

    //This terminal and RequestPty stuff is needed for
    //handling entering sudo passwords. We essentially
    // have to create a fake terminal to run everything in
    //Only needed if connecting to servers in datacenter, not cloud

    if strings.Contains(appConf.Host, "ghx.com") {
        modes := ssh.TerminalModes{
            ssh.TTY_OP_ISPEED: 14400,
            ssh.TTY_OP_OSPEED: 14400,
        }

        err = session.RequestPty("xterm", 80, 40, modes)
        ErrorChecker("Error setting putty garbage", err)
    } else {

    }

    return session
}

func CreateCopyConnection (appConf AppConfig) *ssh.Session {
    //Create the sshconfig
    sshConfig := &ssh.ClientConfig{
        User: appConf.User,
        Auth: []ssh.AuthMethod{
            PublicKeyFile(appConf.PrivateKeyDir, appConf.PrivateKeyFile)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey()}

    host := appConf.Host + ":" + appConf.Port
    connection, err := ssh.Dial("tcp", host, sshConfig)
    ErrorChecker("Unknown Error creating connection to host.", err)

    //create new session
    session, err := connection.NewSession()
    if err != nil {
        panic(err)
    }


    return session
}

//Function to copy a script from one location to the remote server in /var/tmp/
func CopyScript (appConf AppConfig) string {
    //Create a new ssh session to use to copy the script to the server.
    //Then we'll use the original session to execute the script
    scpSession := CreateCopyConnection(appConf)

    //Give the file a tmp file name by adding the timestamp and save this in a var
    t := time.Now().Format("20060102150405")
    _, scriptFileName := filepath.Split(appConf.Script)
    scriptFileNameExt := filepath.Ext(scriptFileName)
    scriptFileNamePrefix := strings.TrimSuffix(scriptFileName, scriptFileNameExt)
    scriptFileName = scriptFileNamePrefix + "_" + t + scriptFileNameExt
    log.Println(scriptFileName)

    //This will copy the file and it's permissions to the remote host. Permissions can be set up to 0755
    //Pro is that it's less complex in the code. Con is that we rely file permissions to
    //be friendly on local file
    err := scp.CopyPath(appConf.Script, appConf.RemoteScriptPath + scriptFileName, scpSession)
    ErrorChecker("Failed to copy script to remote server", err)

    remoteScript := filepath.Clean(appConf.RemoteScriptPath) + "/" + scriptFileName
    log.Printf("Successfully posted file %s to %s\n", appConf.Script, remoteScript  )

    return remoteScript

    //Another way to do the same thing from above, but lets you set the permissions on the file
      //This way seems to top out on 755 permissions even if set higher. Possibly due to remote server configs
      //f, _ := os.Open(appConf.Script)
      //defer f.Close()
      //stat, err := f.Stat()
      //dao.ErrorChecker("Failed getting the file stats for script", err)

      //err = scp.Copy(stat.Size(), 0777, scriptFileName, f, appConf.RemoteScriptPath, scpSession )
      //ErrorChecker("Error copying script to remote server", err)

}

//Function that should be used in a goroutine to read the output of the ssh terminal looking for
//  a prompt to enter the sudo password. Then it enters the sudo password for the user
func SudoPass (config AppConfig, in io.WriteCloser, out io.Reader, output *[]byte) {
    var (
        line string
        r = bufio.NewReader(out)
    )
    for {
        b, err := r.ReadByte()
        if err != nil {
            break
        }

        *output = append(*output, b)

        if b == byte('\n') {
            line = ""
            time.Sleep(5)
            continue
        }

        line += string(b)

        if ( strings.HasPrefix(line, "[sudo] password for ") || strings.HasPrefix(line, "Password") ) && strings.HasSuffix(line, ": ") {
            pw := GetLdapPass(config)
            _, err = in.Write([]byte(pw + "\n"))
            if err != nil {
                break
            }
        }
    }
}

//Function to set the stdin, stdout, and stderr of an ssh session. Returns those values
func SetPipes (remoteSession *ssh.Session) (io.WriteCloser, io.Reader, io.Reader) {
    stdin, err := remoteSession.StdinPipe()
    ErrorChecker("Error setting StdInPipe", err)
    stdout, err := remoteSession.StdoutPipe()
    ErrorChecker("Error setting StdOutPipe", err)
    stderr, err := remoteSession.StderrPipe()
    ErrorChecker("Error creating the stderr pipe", err)
    return stdin, stdout, stderr
}

//Function to execute the script on a remote server
func ExecuteScript (appConf AppConfig, remoteScript string) []byte {
    //Now let's execute the script on the remote server
    //Create a new ssh session. Just in case, add r and x permissions on the script
    runScriptSession := CreateSshConnection(appConf)

    var output []byte
    stdin, stdout, stderr := SetPipes(runScriptSession)
    go io.Copy(os.Stderr, stderr)

    //If running on a linux host in the datacenter, sudo commands will require a password
    if strings.ContainsAny("ghx.com", appConf.Host) {
        go SudoPass(appConf, stdin, stdout, &output)
    }
    command := "chmod +rx " + remoteScript + "; " + remoteScript
    //add start line so the log clearly displays the output from the script
    startScriptMessage := []byte("---------------------------Script output is below this line---------------------------\n")
    for _, byte := range startScriptMessage {
        output = append(output, byte)
    }
    err := runScriptSession.Run(command)
    time.Sleep(1000)

    //add start line so the log clearly displays the output from the script
    endScriptMessage := []byte("\n---------------------------Script output is above this line---------------------------\n")
    for _, byte := range endScriptMessage {
        output = append(output, byte)
    }

    if output != nil {
        log.Println(string(output))
    }

    ErrorChecker("Error executing script on remote server. Exiting", err)

    return output

}

//Function to cleanup the temp script saved on remote server
func CleanupScript (appConf AppConfig, remoteScript string) {
    deleteScriptSession := CreateSshConnection(appConf)
    err := deleteScriptSession.Run("rm -f " + remoteScript)
    ErrorChecker("Error deleting the script from the remote server", err)
    log.Printf("Deleted file %s from remote server", remoteScript)
}

//Function to retrieve the ldap password of a user from AWS SecretsManager
func GetLdapPass (config AppConfig) string {
    //Create new AWS session using local AWS keys Defaults to us-east-1
    //Secret in AWS must be named 'ldap/USERNAME' where USERNAME is substituted with the ldap username
    awsSession, _ := session.NewSession()
    secretSesh := secretsmanager.New(awsSession, aws.NewConfig().WithRegion(config.Region))
    request := &secretsmanager.GetSecretValueInput{
        SecretId: aws.String("ldap/" + config.User),
    }

    //Call secretsmanager to retrieve the SecretString
    result, err := secretSesh.GetSecretValue(request)
    ErrorChecker("Error retrieving password from AWS Secrets", err)

    //The value of SecretString is a string, in json format
    //So convert the string to an array of bytes, then unmarshal it into json
    //Then convert the value from an interface back to a string for use
    var raw map[string]interface{}
    byteResult := []byte(*result.SecretString)
    json.Unmarshal(byteResult, &raw)
    ldapPass := raw["password"].(string)

    return ldapPass
}