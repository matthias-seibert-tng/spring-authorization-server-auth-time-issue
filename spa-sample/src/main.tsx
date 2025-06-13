import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { AuthProvider } from "react-oidc-context";

const oidcConfig = {
	authority: "http://localhost:9000",
	client_id: "messaging-client",
	client_secret: "secret",
	redirect_uri: "http://127.0.0.1:5173",
	scope: "openid",
	client_authentication: "client_secret_basic",
	// ...
};

// biome-ignore lint/style/noNonNullAssertion: <explanation>
createRoot(document.getElementById("root")!).render(
	<StrictMode>
		<AuthProvider {...oidcConfig}>
			<App />
		</AuthProvider>
	</StrictMode>,
);
