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
    <style>
        #passkeyPanel .passkey-section-title {
            margin: 0 0 10px;
            font-size: 20px;
            font-weight: 500;
            color: #2c3e50;
        }
        #passkeyPanel .passkey-muted {
            color: #6f7b85;
            margin-bottom: 12px;
        }
        #passkeyPanel .passkey-table-wrap {
            overflow-x: auto;
            border: 1px solid #d9dee4;
            border-radius: 4px;
        }
        #passkeyPanel .passkey-table {
            margin-bottom: 0;
            background: #fff;
        }
        #passkeyPanel .passkey-table thead th {
            background: #f6f8fa;
            border-bottom: 1px solid #d9dee4;
        }
        #passkeyPanel .passkey-name-label {
            display: inline-block;
            max-width: 260px;
            overflow: hidden;
            text-overflow: ellipsis;
            vertical-align: middle;
            white-space: nowrap;
        }
        #passkeyPanel .passkey-name-input {
            min-width: 180px;
            max-width: 260px;
            display: none;
        }
        #passkeyPanel .passkey-actions .btn {
            margin-right: 4px;
            margin-bottom: 4px;
        }
        #passkeyPanel .passkey-actions .btn:last-child {
            margin-right: 0;
        }
        #passkeyPanel .passkey-add-wrap {
            max-width: 560px;
        }
        #passkeyPanel .passkey-status {
            display: block;
            margin-top: 10px;
            padding: 8px 10px;
            border-radius: 4px;
            border: 1px solid transparent;
            font-weight: 500;
        }
        #passkeyPanel .passkey-status-info {
            color: #3f566b;
            background: #eef4f9;
            border-color: #d2e0ec;
        }
        #passkeyPanel .passkey-status-success {
            color: #237a3b;
            background: #eaf8ee;
            border-color: #cbe9d3;
        }
        #passkeyPanel .passkey-status-error {
            color: #a94442;
            background: #fdeeee;
            border-color: #f4c9c9;
        }
    </style>

    <div id="passkeyPanel" class="panel panel-default" style="border:2px solid #185bb6; border-radius:6px;">
        <div class="panel-heading" style="background:#185bb6; color:#fff; border-radius:4px 4px 0 0;">
            <i class="fa fa-fingerprint"></i> <strong>Passkey Management</strong>
        </div>
        <div class="panel-body" style="padding:20px 22px 18px; background:#fbfcfe;">

            <h4 class="passkey-section-title"><i class="fa fa-list"></i> Registered Devices</h4>
            <div class="passkey-muted">Manage your passkeys and update device labels any time.</div>
            <div id="passkeyDeviceList" class="passkey-table-wrap" aria-live="polite">
                <div style="padding:10px;"><i class="fa fa-spinner fa-spin"></i> Loading...</div>
            </div>

            <hr style="margin:18px 0;">

            <h4 class="passkey-section-title" style="margin-bottom:8px;"><i class="fa fa-plus-circle"></i> Add a New Device</h4>
            <div class="input-group passkey-add-wrap">
                <input type="text" id="deviceNameInput" class="form-control"
                       placeholder="e.g. My iPhone, Work Laptop" maxlength="100" aria-label="Device Name">
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

    function passkeySetStatus(message, tone) {
        var status = document.getElementById('passkeyStatus');
        if (!status) return;
        if (!message) {
            status.style.display = 'none';
            status.innerHTML = '';
            status.className = '';
            return;
        }
        status.style.display = 'block';
        status.className = 'passkey-status passkey-status-' + passkeyEscHtml(tone || 'info');
        status.innerHTML = message;
    }

    function passkeyUpdateSignal(count) {
        document.getElementById('passkey_verified_signal').value = count > 0 ? '1' : '0';
    }

    function passkeyRenderList(devices) {
        var container = document.getElementById('passkeyDeviceList');
        passkeyUpdateSignal(devices.length);
        if (!devices.length) {
            container.innerHTML = '<div style="padding:10px;"><p class="text-muted" style="margin:0;">No devices registered yet. Add one below.</p></div>';
            return;
        }
        var rows = devices.map(function(d) {
            var id = parseInt(d.id, 10);
            var deviceName = d.device_name || 'Unnamed Device';
            return '<tr>' +
                '<td>' +
                '<i class="fa fa-mobile" style="color:#185bb6;"></i>&nbsp;' +
                '<strong id="pkNameLabel_' + id + '" class="passkey-name-label">' + passkeyEscHtml(deviceName) + '</strong>' +
                '<input id="pkNameInput_' + id + '" class="form-control input-sm passkey-name-input" type="text" maxlength="100" value="' + passkeyEscHtml(deviceName) + '">' +
                '</td>' +
                '<td class="text-muted" style="font-size:12px; white-space:nowrap;">' + passkeyEscHtml(d.created_at) + '</td>' +
                '<td class="passkey-actions" style="white-space:nowrap;">' +
                '<button type="button" id="pkEditBtn_' + id + '" class="btn btn-default btn-xs" onclick="passkeyStartEdit(' + id + ')"><i class="fa fa-pencil"></i> Edit</button>' +
                '<button type="button" id="pkSaveBtn_' + id + '" class="btn btn-primary btn-xs" style="display:none;" onclick="passkeySaveEdit(' + id + ', this)"><i class="fa fa-check"></i> Save</button>' +
                '<button type="button" id="pkCancelBtn_' + id + '" class="btn btn-link btn-xs" style="display:none;" onclick="passkeyCancelEdit(' + id + ')">Cancel</button>' +
                '<button type="button" class="btn btn-danger btn-xs" onclick="passkeyDelete(' + id + ', this)"><i class="fa fa-trash"></i> Remove</button>' +
                '</td>' +
                '</tr>';
        });
        container.innerHTML =
            '<table class="table table-condensed table-bordered passkey-table">' +
            '<thead><tr><th>Device Name</th><th>Registered</th><th></th></tr></thead>' +
            '<tbody>' + rows.join('') + '</tbody></table>';
    }

    function passkeyStartEdit(id) {
        var label = document.getElementById('pkNameLabel_' + id);
        var input = document.getElementById('pkNameInput_' + id);
        var editBtn = document.getElementById('pkEditBtn_' + id);
        var saveBtn = document.getElementById('pkSaveBtn_' + id);
        var cancelBtn = document.getElementById('pkCancelBtn_' + id);
        if (!label || !input || !editBtn || !saveBtn || !cancelBtn) return;

        input.value = label.textContent.trim();
        label.style.display = 'none';
        input.style.display = 'inline-block';
        editBtn.style.display = 'none';
        saveBtn.style.display = 'inline-block';
        cancelBtn.style.display = 'inline-block';
        input.focus();
        input.select();
    }

    function passkeyCancelEdit(id) {
        var label = document.getElementById('pkNameLabel_' + id);
        var input = document.getElementById('pkNameInput_' + id);
        var editBtn = document.getElementById('pkEditBtn_' + id);
        var saveBtn = document.getElementById('pkSaveBtn_' + id);
        var cancelBtn = document.getElementById('pkCancelBtn_' + id);
        if (!label || !input || !editBtn || !saveBtn || !cancelBtn) return;

        input.style.display = 'none';
        label.style.display = 'inline-block';
        saveBtn.style.display = 'none';
        cancelBtn.style.display = 'none';
        editBtn.style.display = 'inline-block';
    }

    function passkeySaveEdit(id, btn) {
        var input = document.getElementById('pkNameInput_' + id);
        var label = document.getElementById('pkNameLabel_' + id);
        if (!input || !label) return;

        var nextName = input.value.trim();
        if (!nextName) {
            passkeySetStatus('<i class="fa fa-warning"></i> Please enter a device name.', 'error');
            input.focus();
            return;
        }

        btn.disabled = true;
        fetch(PASSKEY_PROCESS_PATH + '?action=update_passkey_name', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': PASSKEY_CSRF_TOKEN },
            body: JSON.stringify({ id: id, device_name: nextName })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            btn.disabled = false;
            if (data.status === 'success') {
                label.textContent = nextName;
                input.value = nextName;
                passkeyCancelEdit(id);
                passkeySetStatus('<i class="fa fa-check"></i> Device name updated successfully.', 'success');
            } else {
                passkeySetStatus('<i class="fa fa-warning"></i> Failed to update device name: ' + passkeyEscHtml(data.error || 'Unknown error'), 'error');
            }
        })
        .catch(function() {
            btn.disabled = false;
            passkeySetStatus('<i class="fa fa-warning"></i> Request failed while updating device name. Please try again.', 'error');
        });
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
                passkeySetStatus('<i class="fa fa-warning"></i> Failed to load registered devices.', 'error');
            }
        })
        .catch(function() {
            document.getElementById('passkeyDeviceList').innerHTML =
                '<span class="text-danger">Failed to load devices.</span>';
            passkeySetStatus('<i class="fa fa-warning"></i> Failed to load registered devices.', 'error');
        });
    }

    function passkeyDelete(id, btn) {
        if (!confirm('Remove this passkey? You will no longer be able to log in with it.')) return;
        passkeySetStatus('', '');
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
                passkeySetStatus('<i class="fa fa-check"></i> Device removed successfully.', 'success');
                passkeyLoadList();
            } else {
                btn.disabled = false;
                passkeySetStatus('<i class="fa fa-warning"></i> Failed to remove passkey: ' + passkeyEscHtml(data.error || 'Unknown error'), 'error');
            }
        })
        .catch(function() {
            btn.disabled = false;
            passkeySetStatus('<i class="fa fa-warning"></i> Request failed while removing passkey. Please try again.', 'error');
        });
    }

    async function startPasskeyRegistration() {
        if (window.passkeyProcessing) return;
        var btn = document.getElementById('regBtn');
        var deviceName = document.getElementById('deviceNameInput').value.trim() || 'My Device';
        passkeySetStatus('<i class="fa fa-spinner fa-spin"></i> Initialising passkey registration...', 'info');
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
            passkeySetStatus('<i class="fa fa-sync fa-spin"></i> Saving passkey...', 'info');

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
                passkeySetStatus('<i class="fa fa-check"></i> Device registered successfully!', 'success');
                passkeyLoadList();
            } else {
                throw new Error(result.error || 'Registration failed.');
            }
        } catch (err) {
            window.passkeyProcessing = false;
            btn.disabled = false;
            if (err.name !== 'NotAllowedError' && err.name !== 'AbortError') {
                passkeySetStatus('<i class="fa fa-warning"></i> Registration failed: ' + passkeyEscHtml(err.message), 'error');
            } else {
                passkeySetStatus('<i class="fa fa-warning"></i> Passkey registration was cancelled.', 'error');
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
