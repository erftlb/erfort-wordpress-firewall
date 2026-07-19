<?php
/**
 * Two-factor authentication (TOTP).
 *
 * App-based only: Google Authenticator, 1Password, Authy, any RFC 6238 TOTP
 * app. No SMS, no email codes, no cloud, no external service. The shared secret
 * lives in user meta; the QR for enrolment is rendered in the browser from a
 * bundled encoder, so nothing is ever sent anywhere. Ten single-use recovery
 * codes are issued at enrolment for the lost-phone case.
 *
 * Enforcement runs on the wp_authenticate_user filter (after the password is
 * verified, before the session is granted), so a correct password plus a wrong
 * or missing code does not log in.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

/* ---------------------------------------------------------------- settings */

function erf_shield_2fa_on() {
    $o = get_option( 'erf_shield_2fa', array( 'enabled' => 0 ) );
    return ! empty( $o['enabled'] );
}

/* meta keys: _erf_2fa_secret (base32), _erf_2fa_confirmed ('1'), _erf_2fa_codes (array of hashes) */

function erf_shield_2fa_user_active( $user_id ) {
    return '1' === get_user_meta( $user_id, '_erf_2fa_confirmed', true ) && '' !== get_user_meta( $user_id, '_erf_2fa_secret', true );
}

/* ---------------------------------------------------------- TOTP primitives */

/** RFC 4648 base32 alphabet. */
function erf_shield_b32_alphabet() { return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; }

/** Generate a random base32 secret (160 bits -> 32 chars). */
function erf_shield_b32_secret( $len = 32 ) {
    $a = erf_shield_b32_alphabet();
    $s = '';
    $bytes = random_bytes( $len );
    for ( $i = 0; $i < $len; $i++ ) { $s .= $a[ ord( $bytes[ $i ] ) & 31 ]; }
    return $s;
}

/** Decode base32 to raw bytes. */
function erf_shield_b32_decode( $b32 ) {
    $a   = erf_shield_b32_alphabet();
    $b32 = strtoupper( preg_replace( '/[^A-Z2-7]/', '', $b32 ) );
    $bits = '';
    for ( $i = 0, $n = strlen( $b32 ); $i < $n; $i++ ) {
        $v = strpos( $a, $b32[ $i ] );
        if ( false === $v ) { continue; }
        $bits .= str_pad( decbin( $v ), 5, '0', STR_PAD_LEFT );
    }
    $out = '';
    foreach ( str_split( $bits, 8 ) as $chunk ) {
        if ( 8 === strlen( $chunk ) ) { $out .= chr( bindec( $chunk ) ); }
    }
    return $out;
}

/** The 6-digit TOTP for a secret at a given time step. */
function erf_shield_totp( $secret, $timestamp = null, $period = 30, $digits = 6 ) {
    $timestamp = null === $timestamp ? time() : $timestamp;
    $counter   = (int) floor( $timestamp / $period );
    $binctr    = pack( 'N*', 0 ) . pack( 'N*', $counter ); // 64-bit big-endian
    $key       = erf_shield_b32_decode( $secret );
    if ( '' === $key ) { return ''; }
    $hash    = hash_hmac( 'sha1', $binctr, $key, true );
    $offset  = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
    $part    = substr( $hash, $offset, 4 );
    $value   = ( ( ord( $part[0] ) & 0x7f ) << 24 ) | ( ( ord( $part[1] ) & 0xff ) << 16 ) | ( ( ord( $part[2] ) & 0xff ) << 8 ) | ( ord( $part[3] ) & 0xff );
    $otp     = $value % ( 10 ** $digits );
    return str_pad( (string) $otp, $digits, '0', STR_PAD_LEFT );
}

/** Verify a code, allowing +/- one step of clock drift. Constant-time compare. */
function erf_shield_totp_verify( $secret, $code ) {
    $code = preg_replace( '/\D/', '', (string) $code );
    if ( 6 !== strlen( $code ) ) { return false; }
    $now = time();
    foreach ( array( -1, 0, 1 ) as $w ) {
        if ( hash_equals( erf_shield_totp( $secret, $now + ( $w * 30 ) ), $code ) ) { return true; }
    }
    return false;
}

/* ------------------------------------------------------- recovery codes */

function erf_shield_2fa_make_codes( $user_id ) {
    $plain = array();
    $hashes = array();
    for ( $i = 0; $i < 10; $i++ ) {
        $c = strtolower( wp_generate_password( 10, false, false ) );
        $c = substr( $c, 0, 5 ) . '-' . substr( $c, 5, 5 );
        $plain[]  = $c;
        $hashes[] = wp_hash_password( $c );
    }
    update_user_meta( $user_id, '_erf_2fa_codes', $hashes );
    return $plain;
}

/** Consume a recovery code if it matches; returns true and removes it. */
function erf_shield_2fa_use_code( $user_id, $input ) {
    $input  = strtolower( trim( (string) $input ) );
    $hashes = (array) get_user_meta( $user_id, '_erf_2fa_codes', true );
    foreach ( $hashes as $i => $h ) {
        if ( wp_check_password( $input, $h ) ) {
            unset( $hashes[ $i ] );
            update_user_meta( $user_id, '_erf_2fa_codes', array_values( $hashes ) );
            return true;
        }
    }
    return false;
}

/* ---------------------------------------------------------- login enforcement
 * A two-step login: password first (unchanged), then a code. We keep the
 * verified user id in a short signed transient keyed to a one-time token that
 * travels in the second form, so the password is never asked for twice and the
 * second step cannot be replayed. */

add_filter( 'wp_authenticate_user', function ( $user ) {
    if ( function_exists( 'erf_shield_off' ) && erf_shield_off() ) { return $user; } // break glass
    if ( ! erf_shield_2fa_on() || is_wp_error( $user ) ) { return $user; }
    if ( ! erf_shield_2fa_user_active( $user->ID ) ) { return $user; } // user has not enrolled

    // If a 2FA code was submitted with this request, verify it now.
    if ( isset( $_POST['erf_2fa_code'] ) ) {
        $code   = sanitize_text_field( wp_unslash( $_POST['erf_2fa_code'] ) );
        $secret = get_user_meta( $user->ID, '_erf_2fa_secret', true );
        if ( erf_shield_totp_verify( $secret, $code ) || erf_shield_2fa_use_code( $user->ID, $code ) ) {
            return $user; // passed
        }
        if ( function_exists( 'erf_shield_log' ) ) { erf_shield_log( '2fa', 'wrong code for ' . $user->user_login ); }
        return new WP_Error( 'erf_2fa_bad', __( 'That authentication code is not right.' ) );
    }

    // No code yet: bounce to the code prompt. Re-render the login form with a
    // second field, carrying the username/password through so WP can re-auth.
    return new WP_Error( 'erf_2fa_needed', 'erf_2fa_needed' );
}, 30 );

// When the password was right but a code is needed, show the code form instead
// of the generic error. We re-present the login form with only the code field.
add_action( 'login_form', function () {
    if ( ! erf_shield_2fa_on() ) { return; }
    echo '<p class="erf-2fa-row"><label for="erf_2fa_code">' . esc_html__( 'Authentication code', 'default' )
        . '<br><input type="text" name="erf_2fa_code" id="erf_2fa_code" class="input" inputmode="numeric" autocomplete="one-time-code" placeholder="123456 or a recovery code" style="font-size:20px;letter-spacing:.2em"></label></p>';
} );

// Turn our sentinel WP_Error into a clean instruction, not a scary message.
add_filter( 'login_errors', function ( $error ) {
    if ( is_string( $error ) && false !== strpos( $error, 'erf_2fa_needed' ) ) {
        return __( 'Enter the 6-digit code from your authenticator app to finish signing in.', 'default' );
    }
    return $error;
} );

/* ----------------------------------------------------- per-user enrolment UI
 * Each user manages their own 2FA on their profile screen. Admins do not hold
 * anyone else's secret. */

add_action( 'show_user_profile', 'erf_shield_2fa_profile' );
function erf_shield_2fa_profile( $user ) {
    if ( ! erf_shield_2fa_on() ) { return; }
    $active = erf_shield_2fa_user_active( $user->ID );
    $secret = get_user_meta( $user->ID, '_erf_2fa_secret', true );
    if ( ! $active && '' === $secret ) {
        // Provision a pending secret for the QR (not yet confirmed).
        $secret = erf_shield_b32_secret();
        update_user_meta( $user->ID, '_erf_2fa_secret', $secret );
        update_user_meta( $user->ID, '_erf_2fa_confirmed', '' );
    }
    $issuer = rawurlencode( get_bloginfo( 'name' ) );
    $label  = rawurlencode( $user->user_login );
    $otpauth = 'otpauth://totp/' . $issuer . ':' . $label . '?secret=' . $secret . '&issuer=' . $issuer . '&period=30&digits=6';

    wp_enqueue_script( 'erf-shield-qr', ERF_SHIELD_URL . 'assets/qrcode.min.js', array(), ERF_SHIELD_VERSION, true );
    ?>
    <h2>Two-factor authentication</h2>
    <table class="form-table"><tr>
        <th>Status</th>
        <td>
        <?php if ( $active ) : ?>
            <p><strong style="color:#1a7a3c">Active.</strong> This account requires an authenticator code to sign in.</p>
            <p><label><input type="checkbox" name="erf_2fa_disable" value="1"> Turn off two-factor for my account</label></p>
        <?php else : ?>
            <p>Scan this with Google Authenticator, 1Password, or any authenticator app, then enter the 6-digit code it shows to switch it on.</p>
            <div id="erf-2fa-qr" style="width:180px;height:180px;background:#fff;padding:8px;border:1px solid #dcdcde"></div>
            <p style="font-family:ui-monospace,monospace;font-size:12px;margin-top:10px">Manual key: <code><?php echo esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ); ?></code></p>
            <p><label>Enter the code to confirm:<br>
                <input type="text" name="erf_2fa_confirm" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" style="font-size:18px;letter-spacing:.2em;width:160px"></label></p>
            <script>
              (function(){
                function draw(){ if(!window.QRCode){return setTimeout(draw,120);} new QRCode(document.getElementById('erf-2fa-qr'),{text:<?php echo wp_json_encode( $otpauth ); ?>,width:164,height:164,correctLevel:QRCode.CorrectLevel.M}); }
                draw();
              })();
            </script>
        <?php endif; ?>
        </td>
    </tr></table>
    <?php
}

add_action( 'personal_options_update', 'erf_shield_2fa_profile_save' );
function erf_shield_2fa_profile_save( $user_id ) {
    if ( ! erf_shield_2fa_on() || get_current_user_id() !== $user_id ) { return; }

    if ( ! empty( $_POST['erf_2fa_disable'] ) ) {
        delete_user_meta( $user_id, '_erf_2fa_secret' );
        delete_user_meta( $user_id, '_erf_2fa_confirmed' );
        delete_user_meta( $user_id, '_erf_2fa_codes' );
        return;
    }

    if ( ! empty( $_POST['erf_2fa_confirm'] ) && ! erf_shield_2fa_user_active( $user_id ) ) {
        $secret = get_user_meta( $user_id, '_erf_2fa_secret', true );
        $code   = sanitize_text_field( wp_unslash( $_POST['erf_2fa_confirm'] ) );
        if ( $secret && erf_shield_totp_verify( $secret, $code ) ) {
            update_user_meta( $user_id, '_erf_2fa_confirmed', '1' );
            $codes = erf_shield_2fa_make_codes( $user_id );
            // Stash the plaintext codes for one page load so the user can save them.
            set_transient( 'erf_2fa_codes_' . $user_id, $codes, 60 );
            if ( function_exists( 'erf_shield_log' ) ) { erf_shield_log( '2fa', 'enrolled: ' . get_userdata( $user_id )->user_login ); }
        } else {
            // Wrong confirm code: reset the pending secret so they get a fresh QR.
            delete_user_meta( $user_id, '_erf_2fa_secret' );
        }
    }
}

// Show recovery codes once, right after enrolment.
add_action( 'admin_notices', function () {
    $codes = get_transient( 'erf_2fa_codes_' . get_current_user_id() );
    if ( ! $codes ) { return; }
    delete_transient( 'erf_2fa_codes_' . get_current_user_id() );
    echo '<div class="notice notice-warning"><p><strong>Two-factor is on. Save these recovery codes now</strong> - each works once if you lose your phone. They will not be shown again.</p><p style="font-family:ui-monospace,monospace;font-size:14px;letter-spacing:.05em">' . esc_html( implode( '   ', $codes ) ) . '</p></div>';
} );

/* ------------------------------------------------- admin enrolment policy
 * Optional. Once enabled, administrators get a grace window to enrol; after it,
 * an un-enrolled admin can still sign in (so they CAN still enrol) but wp-admin
 * bounces them to their own profile until two-factor is on. That blocks admin
 * use without the chicken-and-egg lockout of refusing the password outright.
 * Break glass (erf_shield_off) overrides it entirely. */

function erf_shield_2fa_policy() {
    return wp_parse_args( get_option( 'erf_shield_2fa', array() ), array(
        'enabled' => 0, 'enforce_admins' => 0, 'grace_days' => 7, 'enforced_since' => 0,
    ) );
}

/** Unix deadline by which $user_id must be enrolled, or 0 if the policy does not apply. */
function erf_shield_2fa_deadline( $user_id ) {
    $p = erf_shield_2fa_policy();
    if ( empty( $p['enabled'] ) || empty( $p['enforce_admins'] ) ) { return 0; }
    if ( ! user_can( $user_id, 'manage_options' ) ) { return 0; }
    $u          = get_userdata( $user_id );
    $registered = $u ? strtotime( $u->user_registered . ' UTC' ) : 0;
    $start      = max( (int) $p['enforced_since'], (int) $registered );
    return $start + max( 0, (int) $p['grace_days'] ) * DAY_IN_SECONDS;
}

/** True when an enforced admin is past grace and still has not enrolled. */
function erf_shield_2fa_must_enrol( $user_id ) {
    if ( ! $user_id ) { return false; }
    if ( function_exists( 'erf_shield_off' ) && erf_shield_off() ) { return false; } // break glass
    $deadline = erf_shield_2fa_deadline( $user_id );
    if ( ! $deadline || erf_shield_2fa_user_active( $user_id ) ) { return false; }
    return time() >= $deadline;
}

/* nag wall: past grace, wp-admin allows only the profile screen until enrolled */
add_action( 'admin_init', function () {
    if ( wp_doing_ajax() ) { return; }
    if ( ! erf_shield_2fa_must_enrol( get_current_user_id() ) ) { return; }
    global $pagenow;
    if ( 'profile.php' === $pagenow ) { return; }
    wp_safe_redirect( admin_url( 'profile.php#erf-2fa-required' ) );
    exit;
}, 1 );

add_action( 'admin_notices', function () {
    if ( ! erf_shield_2fa_must_enrol( get_current_user_id() ) ) { return; }
    echo '<div class="notice notice-error"><p><strong>Two-factor authentication is required for administrators.</strong> Set it up below to regain access to the rest of wp-admin.</p></div>';
} );

/* -------------------------------------------------------- admin section (toggle) */

add_action( 'admin_init', function () {
    if ( ! is_admin() || empty( $_POST['erf_shield_2fa_save'] ) ) { return; }
    if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'erf_shield_2fa' ) ) { return; }
    $prev    = erf_shield_2fa_policy();
    $enforce = empty( $_POST['erf_shield_2fa_enforce'] ) ? 0 : 1;
    update_option( 'erf_shield_2fa', array(
        'enabled'        => empty( $_POST['erf_shield_2fa_enabled'] ) ? 0 : 1,
        'enforce_admins' => $enforce,
        'grace_days'     => isset( $_POST['erf_shield_2fa_grace'] ) ? max( 0, min( 90, (int) $_POST['erf_shield_2fa_grace'] ) ) : (int) $prev['grace_days'],
        // Start the grace clock the first time enforcement is switched on; clear it when off.
        'enforced_since' => $enforce ? ( (int) $prev['enforced_since'] ?: time() ) : 0,
    ) );
} );

add_action( 'erf_shield_page_sections', function () {
    $on = erf_shield_2fa_on();
    $p  = erf_shield_2fa_policy();
    // Per-admin enrolment status, for the operator's awareness.
    $admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login' ) ) );
    ?>
    <div class="box">
      <h2>two-factor authentication</h2>
      <form method="post">
        <?php wp_nonce_field( 'erf_shield_2fa' ); ?>
        <label><input type="checkbox" name="erf_shield_2fa_enabled" <?php checked( $on ); ?>> require app-based TOTP codes. each user enrols on their own profile screen (Users &rarr; your profile). password stays the first factor; a code is the second.</label>
        <label><input type="checkbox" name="erf_shield_2fa_enforce" <?php checked( ! empty( $p['enforce_admins'] ) ); ?>> enforce for administrators: give each admin
          <input type="number" name="erf_shield_2fa_grace" value="<?php echo (int) $p['grace_days']; ?>" min="0" max="90" style="width:60px"> days to enrol, then lock them out of wp-admin (except their own profile) until they do. break glass (<code>wp shield off</code>) always overrides.</label>
        <p style="margin-top:10px"><button class="button button-primary" name="erf_shield_2fa_save" value="1">save</button></p>
      </form>
      <?php if ( $on ) : ?>
        <table style="margin-top:12px">
          <?php foreach ( $admins as $u ) :
              $active   = erf_shield_2fa_user_active( $u->ID );
              $deadline = erf_shield_2fa_deadline( $u->ID );
              if ( $active )        { $cls = 'ok';   $state = 'enrolled'; }
              elseif ( ! $deadline ){ $cls = 'muted'; $state = 'not enrolled'; }
              elseif ( time() >= $deadline ) { $cls = 'warn'; $state = 'OVERDUE - locked out of wp-admin until enrolled'; }
              else { $cls = 'muted'; $state = human_time_diff( time(), $deadline ) . ' left to enrol'; }
          ?>
            <tr><td style="width:170px"><?php echo esc_html( $u->user_login ); ?></td>
                <td class="<?php echo esc_attr( $cls ); ?>"><?php echo esc_html( $state ); ?></td></tr>
          <?php endforeach; ?>
        </table>
      <?php endif; ?>
    </div>
    <?php
} );
