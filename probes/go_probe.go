package main
import ("encoding/json"; "fmt"; "net/http"; "os"; "strconv"; "time")
func main() {
 seconds, _ := strconv.ParseFloat(os.Args[2], 64)
 client := &http.Client{Timeout: time.Duration(seconds*float64(time.Second)), CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
 result := map[string]string{}
 response, err := client.Get(os.Args[1])
 if err != nil { result["state"]="error"; result["detail"]=err.Error() } else { result["state"]="accepted"; result["detail"]=fmt.Sprintf("HTTP %d",response.StatusCode); response.Body.Close() }
 data,_ := json.Marshal(result); fmt.Println("EMUDHRA_JSON:"+string(data))
}
