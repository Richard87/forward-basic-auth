# forward-basic-auth

A simple BasicAuth Forward auth server, takes a username and a bcrypt password hash

It runs the server on port 4000 and uses 3 env variables:
- `AUTH_USERNAME=alice`
- `AUTH_PASSWORD=$2y$10$VhbeCHM9IsG/9n9JU/cN/ufketp3fOhcPCfBxjHKrTYdc4iZRKQ0i` bcrypt hash of "password" or a different better password. Use `htpasswd -nbBC 10 "" password` to generate a new password, replace **password** with your actuall password, and 10 with your "cost".
- `AUTH_REALM=ForwardBasic` Optional real for use in BasicAuth
