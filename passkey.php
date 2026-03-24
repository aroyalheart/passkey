<?php
/**
 * Passkey (WebAuthn) Security Module for WHMCS
 * 100% Secured with AES-256-GCM & CSRF Protection
 * Optimized for Live Production & Sub-folder Installs
 * eHostPK Private Limited
 */

if (!defined("WHMCS")) { die("This file cannot be accessed directly"); }

// ─── Encryption Settings ─────────────────────────────────────────────────────
define('PASSKEY_ENC_KEY', hash('sha256', $cc_encryption_hash, true));

function passkey_encrypt($data) {
    $iv = random_bytes(12);
    $tag = "";
    $ciphertext = openssl_encrypt($data, 'aes-256-gcm', PASSKEY_ENC_KEY, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $ciphertext);
}

// ─── Config ──────────────────────────────────────────────────────────────────
function passkey_config() {
    return [
        "FriendlyName"     => ["Type" => "System", "Value" => "Passkey (Biometric)"],
        "ShortDescription" => ["Type" => "System", "Value" => "Secure passwordless login using TouchID, FaceID or Security Keys."],
        "Description"      => ["Type" => "System", "Value" => "Protected with AES-256-GCM. Multi-session & Sub-folder compatible."],
    ];
}

// ─── Helper: Get Dynamic Path ────────────────────────────────────────────────
function getPasskeyProcessPath() {
    $systemUrl = \WHMCS\Config\Setting::getValue('SystemURL');
    return rtrim($systemUrl, '/') . '/modules/security/passkey/process.php';
}

// ─── Activate (Registration UI) ──────────────────────────────────────────────
function passkey_activate($params) {
    try {
        if (!\WHMCS\Database\Capsule::schema()->hasTable('mod_passkeys')) {
            \WHMCS\Database\Capsule::schema()->create('mod_passkeys', function ($table) {
                $table->increments('id');
                $table->integer('user_id');
                $table->string('user_type', 20);
                $table->text('credential_id'); 
                $table->text('public_key');
                $table->unsignedInteger('counter')->default(0);
                $table->timestamp('created_at')->useCurrent();
                $table->index(['user_id', 'user_type']);
            });
        }
    } catch (\Exception $e) { return "Database Error: " . $e->getMessage(); }

    $csrfToken = bin2hex(random_bytes(32));
    $_SESSION['passkey_csrf_token'] = $csrfToken;
    $processPath = getPasskeyProcessPath();

    return <<<HTML
    <div class="well text-center" style="padding:20px; border:2px dashed #185bb6;">
        <i class="fa fa-fingerprint fa-4x" style="color:#185bb6;"></i>
        <h3>Biometric Setup</h3>
        <p>Linking your device to Passkey Security.</p>
        <button type="button" id="regBtn" class="btn btn-success btn-md" onclick="startPasskeyRegistration()">
            <i class="fa fa-plus"></i> Register This Device
        </button>
        <div id="passkeyStatus" class="margin-top-15" style="display:none;"></div>
        <input type="hidden" name="passkey_verified_signal" id="passkey_verified_signal" value="0">
    </div>

    <script>
    var PASSKEY_CSRF_TOKEN = '{$csrfToken}';
    var PASSKEY_PROCESS_PATH = '{$processPath}';

    async function startPasskeyRegistration() {
        if (window.passkeyProcessing) return;
        var status = document.getElementById('passkeyStatus');
        var btn = document.getElementById('regBtn');
        status.style.display = 'block';
        status.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Initialising...';
        btn.disabled = true;

        try {
            var res = await fetch(PASSKEY_PROCESS_PATH + '?action=get_challenge', {
                credentials: 'include',
                headers: { 'X-CSRF-Token': PASSKEY_CSRF_TOKEN }
            });
            var options = await res.json();
            if (!options || options.status === 'error') throw new Error(options.error || 'Challenge error');

            var toBuffer = (str) => Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

            var credential = await navigator.credentials.create({
                publicKey: {
                    challenge: toBuffer(options.challenge),
                    rp: { name: 'Passkey Security', id: window.location.hostname },
                    user: { id: toBuffer(options.user.id), name: options.user.name, displayName: options.user.displayName },
                    pubKeyCredParams: [{ alg: -7, type: 'public-key' }, { alg: -257, type: 'public-key' }],
                    authenticatorSelection: { userVerification: 'required' },
                    timeout: 60000
                }
            });

            window.passkeyProcessing = true;
            status.innerHTML = '<i class="fa fa-sync fa-spin"></i> Securing Data...';

            var saveRes = await fetch(PASSKEY_PROCESS_PATH + '?action=save_registration', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': PASSKEY_CSRF_TOKEN },
                body: JSON.stringify({
                    id: credential.id,
                    rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    type: credential.type,
                    response: {
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                        attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
                    }
                })
            });

            var result = await saveRes.json();
            if (result.status === 'success') {
                document.getElementById('passkey_verified_signal').value = '1';
                status.innerHTML = '<b class="text-success"><i class="fa fa-check"></i> Verified!</b>';
                setTimeout(() => { 
                    var form = jQuery('#passkey_verified_signal').closest('form').length ? jQuery('#passkey_verified_signal').closest('form') : jQuery('#modalAjax form');
                    form.submit();
                }, 1000);
            } else { throw new Error(result.error); }
        } catch (err) {
            window.passkeyProcessing = false;
            btn.disabled = false;
            if (err.name !== 'NotAllowedError' && err.name !== 'AbortError') {
                status.innerHTML = '<span class="text-danger">Registration failed.</span>';
            } else { status.style.display = 'none'; }
        }
    }
    </script>
HTML;
}

function passkey_activateverify($params) {
    $signal = isset($_POST['passkey_verified_signal']) ? $_POST['passkey_verified_signal'] : App::getFromRequest('passkey_verified_signal');
    if ($signal == '1') { return ["settings" => ["status" => "active"]]; }
    throw new WHMCS\Exception("Biometric verification required.");
}

// ─── Challenge UI (2FA Step) ─────────────────────────────────────────────────
function passkey_challenge($params) {
    $csrfToken = bin2hex(random_bytes(32));
    $_SESSION['passkey_csrf_token'] = $csrfToken;
    $processPath = getPasskeyProcessPath();

    return <<<HTML
    <div align="center" style="padding:20px;">
        <i class="fa fa-shield-alt fa-3x" style="color:#185bb6;"></i>
        <h4>Verification Required</h4>
        <div id="authStatus" style="margin:10px 0; min-height:20px;">Please scan your biometric...</div>
        <button type="button" class="btn btn-success btn-lg btn-block" onclick="startPasskeyAuth(true)">
            <i class="fa fa-fingerprint"></i> Scan Now
        </button>
    </div>

    <script>
    var PASSKEY_CSRF_TOKEN = '{$csrfToken}';
    var PASSKEY_PROCESS_PATH = '{$processPath}';

    async function startPasskeyAuth(isManual) {
        if (window.passkeyAuthenticating) return;
        var status = document.getElementById('authStatus');

        try {
            var res = await fetch(PASSKEY_PROCESS_PATH + '?action=get_challenge', {
                credentials: 'include',
                headers: { 'X-CSRF-Token': PASSKEY_CSRF_TOKEN }
            });
            var options = await res.json();
            if (!options || options.status === 'error') return;

            var toBuffer = (str) => Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

            var assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: toBuffer(options.challenge),
                    rpId: window.location.hostname,
                    userVerification: 'required',
                    timeout: 60000
                },
                mediation: 'optional'
            });

            window.passkeyAuthenticating = true;
            if (status) status.innerHTML = '<i class="fa fa-sync fa-spin"></i> Verifying...';

            var verifyRes = await fetch(PASSKEY_PROCESS_PATH + '?action=verify_login', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': PASSKEY_CSRF_TOKEN },
                body: JSON.stringify({
                    id: assertion.id,
                    response: {
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
                        authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
                        signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)))
                    }
                })
            });

            var result = await verifyRes.json();
            if (result.status === 'success') {
                if (status) status.innerHTML = '<b class="text-success">Success!</b>';
                jQuery('#authStatus').closest('form').submit();
            } else {
                window.passkeyAuthenticating = false;
                if (status) status.innerHTML = '<span class="text-danger">Failed.</span>';
            }
        } catch (err) {
            window.passkeyAuthenticating = false;
            if (isManual && err.name !== 'AbortError' && err.name !== 'NotAllowedError') {
                if (status) status.innerHTML = '<span class="text-danger">Scan failed.</span>';
            }
        }
    }

    (function() { if (window.PublicKeyCredential) setTimeout(() => { startPasskeyAuth(false); }, 500); })();
    </script>
HTML;
}

function passkey_verify($params) {
    return (isset($_SESSION['passkey_verified']) && $_SESSION['passkey_verified'] === true);
}
