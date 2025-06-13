import "./App.css";
import { useAuth } from "react-oidc-context";
import { useEffect } from "react";

const SESSION_TOKEN_STORAGE_KEY = "authTime";

const storeAuthTime = (time: string) => {
	sessionStorage.setItem(SESSION_TOKEN_STORAGE_KEY, time);
};

const getAuthTime = () => sessionStorage.getItem(SESSION_TOKEN_STORAGE_KEY);

const clearAuthTime = () =>
	sessionStorage.removeItem(SESSION_TOKEN_STORAGE_KEY);

function App() {
	const auth = useAuth();

	const authTime: string = auth.user?.id_token?.split(".")[1]
		? JSON.parse(atob(auth.user.id_token.split(".")[1])).auth_time
		: "N/A";
	const previousAuthTime = getAuthTime();

	// Remove query parameters when authenticated and URL contains 'code' parameter
	useEffect(() => {
		if (auth.isAuthenticated) {
			const urlParams = new URLSearchParams(window.location.search);
			if (urlParams.has("code")) {
				const newUrl = `${window.location.protocol}//${window.location.host}${window.location.pathname}`;
				window.history.replaceState({}, document.title, newUrl);
			}
		}
	}, [auth.isAuthenticated]);

	const handleLogin = () => {
		clearAuthTime();
		void auth.signinRedirect();
	};

	const handleRenewToken = () => {
		storeAuthTime(authTime);
		void auth.signinRedirect();
	};

	const handleLogout = () => {
		void auth.removeUser().then(
			() =>
				void auth.signoutRedirect({
					id_token_hint: auth.user?.id_token,
					post_logout_redirect_uri: "http://127.0.0.1:5173",
				}),
		);
	};

	switch (auth.activeNavigator) {
		case "signinSilent":
			return <div>Signing you in...</div>;
		case "signoutRedirect":
			return <div>Signing you out...</div>;
	}

	if (auth.isLoading) {
		return <div>Loading...</div>;
	}

	if (auth.error) {
		return <div>Oops... {auth.error.message}</div>;
	}

	if (auth.isAuthenticated) {
		const authTimeMismatch =
			previousAuthTime &&
			Number.parseInt(previousAuthTime) !== Number.parseInt(authTime);

		return (
			<div>
				<table className="token-info-table">
					<thead>
						<tr>
							<th>Property</th>
							<th>Value</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td>sub</td>
							<td>{auth.user?.profile.sub}</td>
						</tr>
						<tr>
							<td>exp</td>
							<td>{auth.user?.profile.exp}</td>
						</tr>
						<tr className={authTimeMismatch ? "highlight-mismatch" : ""}>
							<td>auth_time</td>
							<td>{authTime}</td>
						</tr>
						{previousAuthTime && (
							<tr className={authTimeMismatch ? "highlight-mismatch" : ""}>
								<td>previous auth_time</td>
								<td>{previousAuthTime}</td>
							</tr>
						)}
					</tbody>
				</table>
				<div className="button-container">
					<button type="button" onClick={handleRenewToken}>
						Renew token
					</button>
					<button type="button" onClick={handleLogout}>
						Log out
					</button>
				</div>
			</div>
		);
	}

	return (
		<button type="button" onClick={handleLogin}>
			Log in
		</button>
	);
}

export default App;
