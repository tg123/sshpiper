# rest challenge plugin for sshpiperd

The rest_challenge plugin will get a challenge from your rest backend and present it to the user. Since the challenge backend is based on your rest webserver, you can add anything you like, from authenticators, SMS OTP, and so on. No need to use any other plugins.


## Usage

```
sshpiperd \
  rest_challenge --url https://localhost:8443/challenge
```

multiple chained challenges possible

```
sshpiperd \
  rest_challenge --url https://localhost:8443/challenge -- \
  rest_challenge --url https://localhost:8443/v2/challenge
```

### options

```
  --url value URL for your rest endpoint, can be anything you like
  --insecure  allow insecure SSL (do not validate SSL certificate)
```

# process example

## Challenge backend: GET https://localhost:8443/challenge/arthur
Upon connection the challenge plugin will send a get request to your endpoint with the /username in the URL that is connecting from the downstream. The content of "message" is then displayed to the user in the session.

```json
{
  "message":"What is the airspeed velocity of an unladen swallow?"
}
```

## Challenge backend: POST https://localhost:8443/challenge/arthur
The user types his response and after hitting enter the plugin will send a post request to your endpoint including /username in the URL. The following data is sent back to your endpoint.

```json
{
  "remoteAddr":"IP and Port of client",
  "uuid":"uniqueID of sshpiperd",
  "response":"response of the client (keyboard interactive)"
}
```

The response is either true or false
```json
{
  "auth":true
}
```

## Skip challenge backend: GET https://localhost:8443/challenge/arthur
You can skip the challenge for a specific connection if you like. For that, instead of sending back the “message” at the first request, just send back the following data.

```json
{
  "challenge":false
}
```