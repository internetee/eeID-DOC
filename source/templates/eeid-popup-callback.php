<?php
/**
 * eeID popup OAuth callback page (PHP variant).
 *
 * Register this script URL as your redirect_uri in eeID manager.
 * Popup mode: postMessages the authorization code to window.opener.
 * Full-page mode: redirects to $fullPageCallbackPath for server-side token exchange.
 *
 * See eeID documentation — Popup authentication.
 */
$fullPageCallbackPath = '/finish.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Signing in…</title>
</head>
<body>
<script>
  (function () {
    var params = new URLSearchParams(window.location.search);
    var payload = {
      type: 'eeid:oauth:callback',
      code: params.get('code'),
      state: params.get('state'),
      error: params.get('error'),
      error_description: params.get('error_description')
    };

    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(payload, window.location.origin);
      window.close();
      return;
    }

    window.location.replace(<?php echo json_encode($fullPageCallbackPath); ?> + window.location.search);
  })();
</script>
<noscript>
  <p>JavaScript is required to complete sign-in. You can close this window and try again.</p>
</noscript>
</body>
</html>
