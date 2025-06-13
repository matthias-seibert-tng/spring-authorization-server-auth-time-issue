# Issue

When using `spring-authorization-server` in combination with `spring-session`, the `auth_time` claim in the ID token is
updated every time a new ID token is issued.

To reproduce:
1. Start the backend:
   - `./gradlew bootRun`
2. Start the frontend
   - `./gradlew npmCi` - install NPM dependencies
   - `./gradlew runDev` - start frontend app
3. Open the demo page at http://127.0.0.1:5173
   - Perform login 
      - Username: `user1`
      - Password: `password`
   - Renew the token

When you change the `sessionRegistry` from `SpringSessionBackedSessionRegistry` to `SessionRegistryImpl`, the issue does
no longer occurs. <br />
See: [DefaultSecurityConfig](src/main/java/com/example/authtimebug/config/DefaultSecurityConfig.java)
