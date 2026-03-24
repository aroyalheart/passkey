async function startPasskeyAuth(isManual = false) {
    if (window.passkeyAuthenticating) return;
    
    const status = document.getElementById('authStatus');
    
    const processPath = "/modules/security/passkey/process.php";

    try {
        // 1. Fetch Challenge
        const response = await fetch(processPath + '?action=get_challenge', { 
            credentials: 'include',
            headers: { 
                'X-CSRF-Token': (typeof PASSKEY_CSRF_TOKEN !== 'undefined') ? PASSKEY_CSRF_TOKEN : '' 
            }
        });
        
        if (!response.ok) throw new Error("Server communication failed (Status: " + response.status + ")");

        const options = await response.json();
        
        if (!options || options.status === 'error' || !options.challenge) {
            if (isManual && status) status.innerHTML = '<span class="text-danger">' + (options.error || "Failed to load challenge") + '</span>';
            return;
        }

        const toBuffer = (str) => Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        const challengeBuffer = toBuffer(options.challenge);

        // 2. Biometric Prompt
        const assertion = await navigator.credentials.get({
            publicKey: { 
                challenge: challengeBuffer, 
                timeout: 60000, 
                rpId: window.location.hostname, 
                userVerification: "required" 
            },
            mediation: 'optional'
        });

        window.passkeyAuthenticating = true;
        if (status) status.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Verifying...';

        // 3. Verify Login
        const verifyRes = await fetch(processPath + '?action=verify_login', {
            method: 'POST',
            credentials: 'include',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': (typeof PASSKEY_CSRF_TOKEN !== 'undefined') ? PASSKEY_CSRF_TOKEN : ''
            },
            body: JSON.stringify({
                id: assertion.id,
                response: {
                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
                    authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
                    signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)))
                }
            })
        });

        const result = await verifyRes.json();

        if (result.status === 'success') {
            if (status) status.innerHTML = '<b class="text-success"><i class="fa fa-check"></i> Success!</b>';
            
            // WHMCS submission logic
            const loginForm = jQuery('#authStatus').closest('form').length ? 
                              jQuery('#authStatus').closest('form') : 
                              jQuery('form').first();
            
            loginForm.submit();
        } else {
            window.passkeyAuthenticating = false;
            if (status) status.innerHTML = '<span class="text-danger">Error: ' + (result.error || "Verification Failed") + '</span>';
        }
    } catch (err) {
        window.passkeyAuthenticating = false;
        if (err.name !== 'AbortError' && err.name !== 'NotAllowedError') {
            if (status) status.innerHTML = '<span class="text-danger">Scan Failed: ' + err.message + '</span>';
        }
    }
}
