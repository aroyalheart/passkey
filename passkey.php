<?php

/**
 * Passkey (WebAuthn) Security Module for WHMCS
 * 100% Secured with AES-256-GCM & CSRF Protection
 * Optimized for Live Production & Sub-folder Installs
 * eHostPK Private Limited
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

// ─── Encryption Settings ─────────────────────────────────────────────────────
define('PASSKEY_ENC_KEY', hash('sha256', $cc_encryption_hash, true));

function passkey_encrypt($data)
{
    $iv = random_bytes(12);
    $tag = "";
    $ciphertext = openssl_encrypt($data, 'aes-256-gcm', PASSKEY_ENC_KEY, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $ciphertext);
}

// ─── Config ──────────────────────────────────────────────────────────────────
function passkey_config()
{
    return [
        "FriendlyName"     => ["Type" => "System", "Value" => "Passkey (Biometric)"],
        "ShortDescription" => ["Type" => "System", "Value" => "Secure passwordless login using TouchID, FaceID or Security Keys."],
        "Description"      => ["Type" => "System", "Value" => "Protected with AES-256-GCM. Multi-session & Sub-folder compatible."],
    ];
}

// ─── Helper: Get Dynamic Path ────────────────────────────────────────────────
function getPasskeyProcessPath()
{
    $systemUrl = \WHMCS\Config\Setting::getValue('SystemURL');
    return rtrim($systemUrl, '/') . '/modules/security/passkey/process.php';
}

// ─── Activate (Registration & Management UI) ─────────────────────────────────
function passkey_activate($params)
{
    try {
        if (!\WHMCS\Database\Capsule::schema()->hasTable('mod_passkeys')) {
            \WHMCS\Database\Capsule::schema()->create('mod_passkeys', function ($table) {
                $table->increments('id');
                $table->integer('user_id');
                $table->string('user_type', 20);
                $table->text('credential_id');
                $table->text('public_key');
                $table->unsignedInteger('counter')->default(0);
                $table->string('device_name', 100)->nullable();
                $table->timestamp('created_at')->useCurrent();
                $table->index(['user_id', 'user_type']);
            });
        } elseif (!\WHMCS\Database\Capsule::schema()->hasColumn('mod_passkeys', 'device_name')) {
            \WHMCS\Database\Capsule::schema()->table('mod_passkeys', function ($table) {
                $table->string('device_name', 100)->nullable()->after('counter');
            });
        }
    } catch (\Exception $e) {
        return "Database Error: " . $e->getMessage();
    }

    $csrfToken = bin2hex(random_bytes(32));
    $_SESSION['passkey_csrf_token'] = $csrfToken;
    $processPath = getPasskeyProcessPath();
    $csrfTokenJs  = json_encode($csrfToken);
    $processPathJs = json_encode($processPath);

    // Pre-set signal to 1 if the user already has passkeys registered
    $adminId = \WHMCS\Session::get("adminid");
    $clientId = \WHMCS\Session::get("uid");
    $userId   = $adminId ?: $clientId;
    $userType = $adminId ? 'admin' : 'client';
    $initialSignal = 0;
    if ($userId) {
        $existing = \WHMCS\Database\Capsule::table('mod_passkeys')
            ->where('user_id', $userId)->where('user_type', $userType)->count();
        $initialSignal = $existing > 0 ? 1 : 0;
    }

    return <<<HTML
    <div class="panel panel-default" style="border:2px solid #185bb6; border-radius:6px;">
        <div class="panel-heading" style="background:#185bb6; color:#fff; border-radius:4px 4px 0 0;">
            <i class="fa fa-fingerprint"></i> <strong>Passkey Management</strong>
        </div>
        <div class="panel-body">

            <h5 style="margin-top:0;"><i class="fa fa-list"></i> Registered Devices</h5>
            <div id="passkeyDeviceList">
                <i class="fa fa-spinner fa-spin"></i> Loading...
            </div>

            <hr style="margin:15px 0;">

            <h5><i class="fa fa-plus-circle"></i> Add a New Device</h5>
            <div class="input-group" style="max-width:440px;">
                <input type="text" id="deviceNameInput" class="form-control"
                       placeholder="e.g. My iPhone, Work Laptop" maxlength="100">
                <span class="input-group-btn">
                    <button type="button" id="regBtn" class="btn btn-success" onclick="startPasskeyRegistration()">
                        <i class="fa fa-fingerprint"></i> Register Device
                    </button>
                </span>
            </div>
            <div id="passkeyStatus" style="display:none; margin-top:8px;"></div>

        </div>
    </div>
    <input type="hidden" name="passkey_verified_signal" id="passkey_verified_signal" value="{$initialSignal}">

    <script>
    var PASSKEY_CSRF_TOKEN = {$csrfTokenJs};
    var PASSKEY_PROCESS_PATH = {$processPathJs};

    function passkeyEscHtml(str) {
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function passkeyUpdateSignal(count) {
        document.getElementById('passkey_verified_signal').value = count > 0 ? '1' : '0';
    }

    function passkeyRenderList(devices) {
        var container = document.getElementById('passkeyDeviceList');
        passkeyUpdateSignal(devices.length);
        if (!devices.length) {
            container.innerHTML = '<p class="text-muted" style="margin:0;">No devices registered yet. Add one below.</p>';
            return;
        }
        var rows = devices.map(function(d) {
            return '<tr>' +
                '<td><i class="fa fa-mobile-alt" style="color:#185bb6;"></i>&nbsp;<strong>' + passkeyEscHtml(d.device_name || 'Unnamed Device') + '</strong></td>' +
                '<td class="text-muted" style="font-size:12px; white-space:nowrap;">' + passkeyEscHtml(d.created_at) + '</td>' +
                '<td style="white-space:nowrap;"><button type="button" class="btn btn-danger btn-xs" onclick="passkeyDelete(' + parseInt(d.id, 10) + ', this)">' +
                '<i class="fa fa-trash"></i> Remove</button></td>' +
                '</tr>';
        });
        container.innerHTML =
            '<table class="table table-condensed table-bordered" style="margin-bottom:0;">' +
            '<thead><tr><th>Device Name</th><th>Registered</th><th></th></tr></thead>' +
            '<tbody>' + rows.join('') + '</tbody></table>';
    }

    function passkeyLoadList() {
        fetch(PASSKEY_PROCESS_PATH + '?action=list_passkeys', {
            credentials: 'include',
            headers: { 'X-CSRF-Token': PASSKEY_CSRF_TOKEN }
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success') {
                passkeyRenderList(data.passkeys);
            } else {
                document.getElementById('passkeyDeviceList').innerHTML =
                    '<span class="text-danger">Failed to load devices.</span>';
            }
        })
        .catch(function() {
            document.getElementById('passkeyDeviceList').innerHTML =
                '<span class="text-danger">Failed to load devices.</span>';
        });
    }

    function passkeyDelete(id, btn) {
        if (!confirm('Remove this passkey? You will no longer be able to log in with it.')) return;
        btn.disabled = true;
        fetch(PASSKEY_PROCESS_PATH + '?action=delete_passkey', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': PASSKEY_CSRF_TOKEN },
            body: JSON.stringify({ id: id })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success') {
                passkeyLoadList();
            } else {
                btn.disabled = false;
                alert('Failed to remove passkey: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(function() { btn.disabled = false; alert('Request failed. Please try again.'); });
    }

    async function startPasskeyRegistration() {
        if (window.passkeyProcessing) return;
        var status = document.getElementById('passkeyStatus');
        var btn = document.getElementById('regBtn');
        var deviceName = document.getElementById('deviceNameInput').value.trim() || 'My Device';
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

            var toBuffer = function(str) {
                return Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), function(c) { return c.charCodeAt(0); });
            };

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
            status.innerHTML = '<i class="fa fa-sync fa-spin"></i> Saving...';

            var saveRes = await fetch(PASSKEY_PROCESS_PATH + '?action=save_registration', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': PASSKEY_CSRF_TOKEN },
                body: JSON.stringify({
                    id: credential.id,
                    device_name: deviceName,
                    rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId))),
                    type: credential.type,
                    response: {
                        clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.clientDataJSON))),
                        attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.attestationObject)))
                    }
                })
            });

            var result = await saveRes.json();
            window.passkeyProcessing = false;
            btn.disabled = false;

            if (result.status === 'success') {
                document.getElementById('deviceNameInput').value = '';
                status.innerHTML = '<b class="text-success"><i class="fa fa-check"></i> Device registered successfully!</b>';
                passkeyLoadList();
            } else {
                throw new Error(result.error || 'Registration failed.');
            }
        } catch (err) {
            window.passkeyProcessing = false;
            btn.disabled = false;
            if (err.name !== 'NotAllowedError' && err.name !== 'AbortError') {
                status.innerHTML = '<span class="text-danger">Registration failed: ' + passkeyEscHtml(err.message) + '</span>';
            } else {
                status.style.display = 'none';
            }
        }
    }

    passkeyLoadList();
    </script>
HTML;
}

function passkey_activateverify($params)
{
    $signal = isset($_POST['passkey_verified_signal']) ? $_POST['passkey_verified_signal'] : App::getFromRequest('passkey_verified_signal');
    if ($signal == '1') {
        return ["settings" => ["status" => "active"]];
    }
    throw new WHMCS\Exception("Biometric verification required.");
}

// ─── Challenge UI (2FA Step) ─────────────────────────────────────────────────
function passkey_challenge($params)
{
    $csrfToken = bin2hex(random_bytes(32));
    $_SESSION['passkey_csrf_token'] = $csrfToken;
    $processPath = getPasskeyProcessPath();
    $csrfTokenJs  = json_encode($csrfToken);
    $processPathJs = json_encode($processPath);

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
    var PASSKEY_CSRF_TOKEN = {$csrfTokenJs};
    var PASSKEY_PROCESS_PATH = {$processPathJs};

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

function passkey_verify($params)
{
    return (isset($_SESSION['passkey_verified']) && $_SESSION['passkey_verified'] === true);
}
