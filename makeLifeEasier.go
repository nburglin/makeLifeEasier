package main

import (
    "makeLifeEasier/dao"
    "log"
    "strings"
    "flag"
    "path/filepath"
    "io"
    "os"
    "github.com/gorilla/mux"
    "net/http"
    "encoding/json"
    "io/ioutil"
    "time"
)

func ImportFlags () string {
    var configFile string
    flag.StringVar(&configFile, "configFile", "", "Name of the config file to use. Does not require extension")
    flag.Parse()

    if configFile == "" {
        log.Fatalln("No 'configFile' flag was supplied. This is a required argument to pass")
    }

    return configFile
}

func DisplayInfo (w http.ResponseWriter, r *http.Request) {
    var message dao.DefaultPageReturn
    message.Message = "This is the default landing page. To list available configurations to execute, use the uri /config/{configname}"
    json.NewEncoder(w).Encode(message)
    log.Println("Base URI accessed. URI: /")
}

func ExecuteRemoteApp (w http.ResponseWriter, r *http.Request) {
    log.Println("URI accessed: /configs/")
    log.Println("Method: POST")
    params := mux.Vars(r)
    log.Printf("Params are: %s", params)
    appLog := RunApp(params["configname"])
    var message dao.DefaultPageReturn
    message.Message = string(appLog)
    json.NewEncoder(w).Encode(message)
}

func GetAvailableConfigs (w http.ResponseWriter, r *http.Request) {
    configs, err := ioutil.ReadDir(configPath)
    response := dao.AvailableConfigsJSON{}
    log.Println("URI accessed: /configs/")
    if err != nil {
        log.Fatalf("Error reading files in configpath. Error: %v", err)
    }
    response.Count = len(configs)
    if response.Count == 0 {
        response.Message = "There are no configs available"
    }
    log.Println("Available Configs:")
    for _, file := range configs {
        response.Files = append(response.Files, file.Name())
        log.Printf("\t%s", file.Name())
    }
    json.NewEncoder(w).Encode(response)
}

//Request received from Google Home
func ExecuteRemoteAppFromGoogle (w http.ResponseWriter, r *http.Request) {
    //Set Header on response to Google
    w.Header().Set("Content-Type", "appliation/json")

    params := mux.Vars(r)
    log.Printf("Params are: %s", params)

    RunApp(params["configname"])
}

func RunApp (configFile string) []byte {
    //Initial read of config file
    var appConf dao.AppConfig
    appConf = dao.ReadConfigs(strings.TrimSuffix(configFile, filepath.Ext(configFile)), configPath)

    //Setup a slice of strings to pass back the log messages to the API call
    //appLog := []string{}

    //Set up SSH config info and create new session
    session := dao.CreateSshConnection(appConf)

    log.Printf("Config File Contents: %+v", appConf)
    var output []byte
    var commandOutput []byte

    //Check the config file if there is a script to copy to the server and execute
    //We do this first. So if there are both a script AND commands, we execute
    //the script followed by commands.
    if appConf.Script != "" {
        //Copy script to the remote server and return the full path to the script
        log.Println("Script detected.")
        remoteScript:= dao.CopyScript(appConf)
        log.Println("Script copied successfully")
        //Execute the script on the remote server
        output = dao.ExecuteScript(appConf, remoteScript)

        //And now we need to clean up that script from the remote server
        if appConf.DeleteOnDisconnect {
            dao.CleanupScript(appConf, remoteScript)
        }
    }

    //Now check if there are commands in the config file and run them
    if appConf.Commands != nil {
        //Combine the array of commands together in one line
        //ssh can only really send 1 command per connection,
        // so we combine them all in a single line and use
        // ';' between them as bash knows this designates separate commands
        log.Println("Executing separate commands")
        command := strings.Join(appConf.Commands, "; ")


        stdin, stdout, stderr := dao.SetPipes(session)
        go io.Copy(os.Stderr, stderr)
        if strings.ContainsAny("ghx.com", appConf.Host) {
            go dao.SudoPass(appConf, stdin, stdout, &commandOutput)
        }
        err := session.Run(command)
        dao.ErrorChecker("Error running command", err)
        //Add this sleep to get rid of race condition where not all of command output would display
        time.Sleep(1000)

        log.Println(string(commandOutput))

    }

    //combine command output with the output of script to return to API
    for _, byte := range commandOutput {
        output = append(output, byte)
    }

    return output
}



//Set the configPath variable as a global variable
var appDirectory, err = os.Getwd()
var configPath = appDirectory + "/config/"

func main() {
    //Set filepath where the config files will be located
    dao.ErrorChecker("Unable to set the Application Directory.", err)


    //Set up a router for APIs
    router := mux.NewRouter()
    router.HandleFunc("/", DisplayInfo).Methods("GET")
    router.HandleFunc("/configs", GetAvailableConfigs).Methods("GET")
    router.HandleFunc("/configs/", GetAvailableConfigs).Methods("GET")
    router.HandleFunc("/configs/{configname}", ExecuteRemoteApp).Methods("POST")
    router.HandleFunc("/configs/google", ExecuteRemoteAppFromGoogle).Methods("POST")

    log.Fatal(http.ListenAndServe(":8000", router))


//moved all of the below into separate function to be called if the API gets hit.
    //Initial read of config file
//    configFile := ImportFlags()
//    var appConf dao.AppConfig
//    appConf = dao.ReadConfigs(strings.TrimSuffix(configFile, filepath.Ext(configFile)), configPath)

    //Set up SSH config info and create new session
//    session := dao.CreateSshConnection(appConf)

//    log.Printf("%+v", appConf)

    //Check the config file if there is a script to copy to the server and execute
    //We do this first. So if there are both a script AND commands, we execute
    //the script followed by commands.
//    if appConf.Script != "" {
        //Copy script to the remote server and return the full path to the script
//        log.Println("Script detected.")
//        remoteScript:= dao.CopyScript(appConf)
//        log.Println("Script copied successfully")
        //Execute the script on the remote server
//        dao.ExecuteScript(appConf, remoteScript)

        //And now we need to clean up that script from the remote server
//        if appConf.DeleteOnDisconnect {
//            dao.CleanupScript(appConf, remoteScript)
//        }
//    }

    //Now check if there are commands in the config file and run them
//    if appConf.Commands != nil {
        //Combine the array of commands together in one line
        //ssh can only really send 1 command per connection,
        // so we combine them all in a single line and use
        // ';' between them as bash knows this designates separate commands
//        log.Println("Executing separate commands")
//        command := strings.Join(appConf.Commands, "; ")

//        var output []byte
//        stdin, stdout, stderr := dao.SetPipes(session)
//        go io.Copy(os.Stderr, stderr)
//        go dao.SudoPass(appConf, stdin, stdout, &output)
//        err := session.Run(command)
//        dao.ErrorChecker("Error running command", err)

//        log.Println(string(output))
//    }
}
