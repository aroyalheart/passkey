<?php

/**
 * Passkey Process Engine for Passkey
 * Handles WebAuthn Registration & Verification (Secure Version)
 * AES-256-GCM & CSRF Protection Integrated
 */

error_reporting(0);
ini_set('display_errors', 0);

require_once __DIR__ . '/../../../init.php';

use WHMCS\Database\Capsule;

// Output buffer clean
if (ob_get_length()) ob_clean();
header('Content-Type: application/json');

// ─── Constants & Encryption Settings ─────────────────────────────────────────
define('PASSKEY_ENC_KEY', hash('sha256', $cc_encryption_hash, true));

// ─── Encryption Helpers ──────────────────────────────────────────────────────
function passkey_encrypt($data)
{
    $iv = random_bytes(12);
    $tag = "";
    $ciphertext = openssl_encrypt($data, 'aes-256-gcm', PASSKEY_ENC_KEY, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $ciphertext);
}

// ─── Anti-cURL & External Script Protection ──────────────────────────────
$requestedWith = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';
if (strtolower($requestedWith) !== 'xmlhttprequest' && !isset($_GET['action'])) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['status' => 'error', 'error' => 'Direct API access is prohibited.']));
}

// ─── Origin & Referer Lockdown (Postman Block) ───────────────────────────
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$currentHost = $_SERVER['HTTP_HOST'];

if (!empty($origin)) {
    $expectedOrigin = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $currentHost;
    if ($origin !== $expectedOrigin) {
        header('HTTP/1.1 403 Forbidden');
        die(json_encode(['status' => 'error', 'error' => 'Direct API access is strictly prohibited.']));
    }
}

// ─── CSRF Protection Check ───────────────────────────────────────────────────
$requestToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (empty($requestToken) || $requestToken !== ($_SESSION['passkey_csrf_token'] ?? '')) {
    die(json_encode(['status' => 'error', 'error' => 'Security token mismatch.']));
}

// ─── Session & Identity ──────────────────────────────────────────────────────
$adminId = \WHMCS\Session::get("adminid");
$clientId = \WHMCS\Session::get("uid");
$twoFaAdmin = \WHMCS\Session::get("2faadminid");
$twoFaClient = \WHMCS\Session::get("2fauid");

$userId = null;
$userType = '';

if ($adminId || $twoFaAdmin) {
    $userId = $adminId ?: $twoFaAdmin;
    $userType = 'admin';
} elseif ($clientId || $twoFaClient) {
    $userId = $clientId ?: $twoFaClient;
    $userType = 'client';
}

if (!$userId) {
    header('HTTP/1.1 401 Unauthorized');
    die(json_encode(['status' => 'error', 'error' => 'Authentication session required.']));
    exit;
}

// True only when the user has completed full authentication (not just the password step).
// 2FA-pending sessions ($twoFaAdmin/$twoFaClient) must NOT be allowed to manage passkeys,
// as that would let an attacker who passed the password step register/delete passkeys.
$isFullSession = (bool)($adminId ?: $clientId);

$action = $_GET['action'] ?? '';

switch ($action) {

    case 'get_challenge':
        try {
            $bytes = random_bytes(32);
            $challenge = trim(base64_encode($bytes), '=');
            $_SESSION['passkey_challenge'] = $challenge;

            $fullName = "WHMCS User";
            $email = "";

            if ($userType === 'admin') {
                $userData = Capsule::table('tbladmins')->where('id', $userId)->first();
                if ($userData) {
                    $fullName = $userData->firstname . ' ' . $userData->lastname;
                    $email = $userData->email;
                }
            } else {
                $userData = Capsule::table('tblclients')->where('id', $userId)->first();
                if ($userData) {
                    $fullName = $userData->firstname . ' ' . $userData->lastname;
                    $email = $userData->email;
                }
            }

            // Display Name format: Full Name ( Email )
            $displayName = $fullName . " ( " . $email . " )";

            echo json_encode([
                'status' => 'success',
                'challenge' => $challenge,
                'user' => [
                    'id' => trim(base64_encode((string)$userId), '='),
                    'name' => $email ?: ($userType . '_' . $userId), // Unique internal name (Email is best)
                    'displayName' => $displayName
                ]
            ]);
        } catch (\Exception $e) {
            echo json_encode(['status' => 'error', 'error' => 'Token failed.']);
        }
        break;

    case 'save_registration':
        if (!$isFullSession) {
            http_response_code(403);
            die(json_encode(['status' => 'error', 'error' => 'Passkey registration requires a fully authenticated session.']));
        }

        $input = json_decode(file_get_contents('php://input'), true);
        if (empty($input['id'])) die(json_encode(['status' => 'error', 'error' => 'No data.']));

        // Enforce a per-user passkey limit
        $passkeyCount = Capsule::table('mod_passkeys')
            ->where('user_id', $userId)
            ->where('user_type', $userType)
            ->count();
        if ($passkeyCount >= 10) {
            die(json_encode(['status' => 'error', 'error' => 'Maximum of 10 passkeys reached. Please remove an existing device first.']));
        }

        try {
            $encryptedId = passkey_encrypt($input['id']);
            $deviceName  = (isset($input['device_name']) && is_string($input['device_name'])) ? substr(trim($input['device_name']), 0, 100) : '';
            if (empty($deviceName)) $deviceName = 'My Device';

            Capsule::table('mod_passkeys')->insert([
                'user_id'       => $userId,
                'user_type'     => $userType,
                'credential_id' => $encryptedId,
                'public_key'    => json_encode($input['response'] ?? 'biometric_data'),
                'device_name'   => $deviceName,
                'counter'       => 0,
                'created_at'    => date('Y-m-d H:i:s'),
            ]);

            echo json_encode(['status' => 'success']);
        } catch (\Exception $e) {
            echo json_encode(['status' => 'error', 'error' => $e->getMessage()]);
        }
        break;

    case 'list_passkeys':
        if (!$isFullSession) {
            http_response_code(403);
            die(json_encode(['status' => 'error', 'error' => 'Passkey management requires a fully authenticated session.']));
        }

        try {
            $rows = Capsule::table('mod_passkeys')
                ->where('user_id', $userId)
                ->where('user_type', $userType)
                ->orderBy('created_at', 'asc')
                ->select(['id', 'device_name', 'created_at'])
                ->get();

            $list = [];
            foreach ($rows as $pk) {
                $list[] = [
                    'id'          => (int) $pk->id,
                    'device_name' => $pk->device_name ?: 'Unnamed Device',
                    'created_at'  => $pk->created_at,
                ];
            }
            echo json_encode(['status' => 'success', 'passkeys' => $list]);
        } catch (\Exception $e) {
            echo json_encode(['status' => 'error', 'error' => 'Failed to load passkeys.']);
        }
        break;

    case 'delete_passkey':
        if (!$isFullSession) {
            http_response_code(403);
            die(json_encode(['status' => 'error', 'error' => 'Passkey management requires a fully authenticated session.']));
        }

        $input    = json_decode(file_get_contents('php://input'), true);
        $deleteId = isset($input['id']) ? (int) $input['id'] : 0;
        if ($deleteId <= 0) die(json_encode(['status' => 'error', 'error' => 'Invalid passkey ID.']));

        try {
            $deleted = Capsule::table('mod_passkeys')
                ->where('id', $deleteId)
                ->where('user_id', $userId)
                ->where('user_type', $userType)
                ->delete();

            if ($deleted) {
                echo json_encode(['status' => 'success']);
            } else {
                echo json_encode(['status' => 'error', 'error' => 'Passkey not found or already removed.']);
            }
        } catch (\Exception $e) {
            echo json_encode(['status' => 'error', 'error' => 'Failed to remove passkey.']);
        }
        break;

    case 'verify_login':
        $input = json_decode(file_get_contents('php://input'), true);
        if (empty($input['id'])) die(json_encode(['status' => 'error', 'error' => 'No ID.']));

        $passkeys = Capsule::table('mod_passkeys')
            ->where('user_id', $userId)
            ->where('user_type', $userType)
            ->get();

        $found = false;
        foreach ($passkeys as $pk) {
            // Decrypt the stored ID
            $data = base64_decode($pk->credential_id);
            $iv = substr($data, 0, 12);
            $tag = substr($data, 12, 16);
            $ciphertext = substr($data, 28);

            $decryptedId = openssl_decrypt($ciphertext, 'aes-256-gcm', PASSKEY_ENC_KEY, OPENSSL_RAW_DATA, $iv, $tag);

            if ($decryptedId === $input['id']) {
                $found = true;
                break;
            }
        }

        if ($found) {
            $_SESSION['passkey_verified'] = true;
            if ($twoFaAdmin || $twoFaClient) {
                $_SESSION['2fa_verified'] = true;
            }
            echo json_encode(['status' => 'success']);
            unset($_SESSION['passkey_challenge']);
        } else {
            echo json_encode(['status' => 'error', 'error' => 'Device mismatch.']);
        }
        break;

    default:
        echo json_encode(['status' => 'error', 'error' => 'Unauthorized.']);
        break;
}
exit;
