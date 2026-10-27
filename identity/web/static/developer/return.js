// Where a sign-in started from the developer portal returns. The identity service puts a token in the URL fragment;
// this page never reads it. The sign-in already set the session cookie the portal uses, so: drop the fragment from
// the address bar and go to the portal.
history.replaceState(null, "", location.pathname);
location.replace("/developer/services");
