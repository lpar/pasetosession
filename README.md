# pasetosession

This library builds on the PASETO standard to provide session utilities for web applications in Go.

Key features:

 - Tokens are issued as HttpOnly cookies to [mitigate XSS attacks][1].

 - A cache of spent token JTI values is used to [help prevent session hijacking][2] and 
 implement session timeouts via [renewal timeout][3].

 - Two applications using the same secret key can federate their
 authentication, assuming they can share the appropriate cookie.

 - You can add arbitrary data to the session object, subject to cookie size
limits, and retrieve the information from the Context in your Go HTTP
handlers.

 - Standard Handler wrappers are provided to refresh the session, decode it and put its data in the Context, mandate a valid session / authenticated user, log out the user / delete the session.

The basic idea is that each time the user loads a web page wrapped in one of the session handlers, the session token is recorded as used in memory, and a new token is issued.

Check the example folder for a simple demo app. The basic idea is:

 - Prompt user to log in and verify the credentials supplied. (This part is your problem.)
 - Create a token with the verified user information in, and call TokenToCookie to send it to the
   browser.
 - Wrap all pages which should be restricted to authenticated users in the Authenticate wrapper.
 - Wrap all other pages with the Refresh handler.
 - Make the logout URL call the DeleteCookie handler.

## Limitations and defects

If you have multiple applications using the same secret key, a session token used in one application can be used one more time in another. (Avoiding this would require keeping a proper
session database shared between the applications.)

If you need to store more session information than will fit in a cookie after encoding and encryption overhead, you're out of luck.

No actual login page implementation is supplied. It's up to you to build that in a suitable safe way. (My use case was session handling after an external enterprise SSO system
has been used to log in.)

If you need to be able to invalidate some but not all sessions on demand, this is the wrong solution.

 [1]: https://www.owasp.org/index.php/HttpOnly
 [2]: https://www.owasp.org/index.php/Session_fixation
 [3]: https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Renewal_Timeout