# forward-basic-auth

A simple BasicAuth Forward auth server, takes a username and a bcrypt password hash

It runs the server on port 4000 and uses 3 env variables:
- `AUTH_USERNAME=alice`
- `AUTH_PASSWORD=$2y$10$VhbeCHM9IsG/9n9JU/cN/ufketp3fOhcPCfBxjHKrTYdc4iZRKQ0i` bcrypt hash of "password" or a different better password. Use `htpasswd -nbBC 10 "" password` to generate a new password, replace **password** with your actuall password, and 10 with your "cost".
- `AUTH_REALM=ForwardBasic` Optional real for use in BasicAuth
- `AUTH_COOKIE` Rename the cookie name, defaults to `forward_auth_id`
- `AUTH_HASH_KEY` Optional hash key, 32 byte hex encoded random string for use to Sign cookies. If not set, a random key will be generated on startup.
- `ALLOW_OPTION_REQ`: If set to `yes`, allow all option requests (used for pre-flight request in relation to CORS)
- `DEBUG`: If set to `yes`, include all requests in log (including all headers!)

## To run the Auth Server:

```shell
docker run --rm -it -p 4000:4000 \
  -e AUTH_USERNAME=alice \
  -e AUTH_PASSWORD=\$2y\$10\$VhbeCHM9IsG/9n9JU/cN/ufketp3fOhcPCfBxjHKrTYdc4iZRKQ0i \
  ghcr.io/richard87/forward-basic-auth:latest
```

Then go to http://127.0.0.1:4000/authorize and log in with the username `alice` and the password `password`


## Traefik

The middleware must set `trustForwardHeader` to `true` 

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: forward-auth
spec:
  forwardAuth:
    address: http://basic-auth.development/authorize # service-name.namespace
    trustForwardHeader: true
```

## TODO:
- Accept a htpasswd file