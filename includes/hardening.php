<?php
/**
 * Extra hardening: a Content-Security-Policy header builder and session controls.
 *
 * CSP is the pro-grade header the core plugin's basic set does not include. It
 * is powerful and easy to get wrong (a strict policy can blank a page), so it
 * ships OFF, with a report-only mode to test a policy before enforcing it, and
 * a sensible starter value the operator can edit.
 *
 * Session controls: an idle-timeout that logs a user out after inactivity, and
 * a one-click "log everyone out everywhere" for the "I think I was phished"
 * moment. Both use WordPress's own session token store, no new tables.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

function erf_shield_harden() {
    return wp_parse_args( get_option( 'erf_shield_harden', array() ), array(
        'csp_on'      => 0,
        'csp_report'  => 1,   // report-only by default when first enabled
        'csp_value'   => "default-src 'self'; img-src 'self' data: https:; media-src 'self' https:; style-src 'self' 'unsafe-inline' https:; font-src 'self' https: data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; frame-ancestors 'self'; base-uri 'self'; object-src 'none'",
        'idle_on'     => 0,
        'idle_mins'   => 60,
        'app_pw_off'  => 0,   // turn off application passwords entirely
        'rest_auth'   => 0,   // require login for the REST API
    ) );
}

/* ---------------------------------------------------- api surface
 * Two opt-in reductions of the REST/app-password attack surface for sites that
 * do not need them. Both OFF by default: the block editor and some plugins use
 * authenticated REST (unaffected), but a public site rarely needs anonymous REST
 * reads or application passwords at all. */

add_filter( 'wp_is_application_passwords_available', function ( $available ) {
    return ! empty( erf_shield_harden()['app_pw_off'] ) ? false : $available;
} );

add_filter( 'rest_authentication_errors', function ( $result ) {
    if ( ! empty( $result ) ) { return $result; }               // another handler already ruled
    if ( empty( erf_shield_harden()['rest_auth'] ) ) { return $result; }
    if ( ! is_user_logged_in() ) {
        return new WP_Error( 'erf_rest_forbidden', 'The REST API is restricted to signed-in users on this site.', array( 'status' => 401 ) );
    }
    return $result;
} );

/* -------------------------------------------------------- CSP header */

add_action( 'send_headers', function () {
    $h = erf_shield_harden();
    if ( empty( $h['csp_on'] ) || is_admin() ) { return; } // never risk the admin UI
    $value = trim( (string) $h['csp_value'] );
    if ( '' === $value ) { return; }
    $header = ! empty( $h['csp_report'] ) ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
    header( $header . ': ' . $value );
}, 20 );

/* ---------------------------------------------------- idle timeout
 * On each authenticated request we stamp the last-seen time in a short cookie
 * (signed by wp_auth so it cannot be forged). If the gap exceeds the limit, the
 * session is destroyed and the user is bounced to login. */

add_action( 'init', function () {
    if ( function_exists( 'erf_shield_off' ) && erf_shield_off() ) { return; } // break glass
    $h = erf_shield_harden();
    if ( empty( $h['idle_on'] ) || ! is_user_logged_in() ) { return; }
    $limit = max( 5, (int) $h['idle_mins'] ) * MINUTE_IN_SECONDS;
    $uid   = get_current_user_id();
    $key   = 'erf_shield_seen_' . $uid;
    $last  = (int) get_user_meta( $uid, $key, true );
    $now   = time();

    if ( $last && ( $now - $last ) > $limit ) {
        update_user_meta( $uid, $key, 0 );
        if ( function_exists( 'erf_shield_log' ) ) { erf_shield_log( 'session', 'idle timeout for user ' . $uid ); }
        wp_logout();
        wp_safe_redirect( wp_login_url() );
        exit;
    }
    // Throttle the write: only stamp once a minute.
    if ( $now - $last > 60 ) { update_user_meta( $uid, $key, $now ); }
} );

/* ---------------------------------------------------- admin section */

add_action( 'admin_init', function () {
    if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) { return; }

    if ( ! empty( $_POST['erf_shield_harden_save'] ) && check_admin_referer( 'erf_shield_harden' ) ) {
        $in  = wp_unslash( $_POST );
        // Each box carries a hidden marker and only its own keys are touched, so
        // saving one box never resets another's toggles.
        $cur = erf_shield_harden();
        if ( isset( $in['erf_shield_csp_box'] ) ) {
            $cur['csp_on']     = empty( $in['csp_on'] ) ? 0 : 1;
            $cur['csp_report'] = empty( $in['csp_report'] ) ? 0 : 1;
            $cur['csp_value']  = isset( $in['csp_value'] ) ? sanitize_text_field( $in['csp_value'] ) : '';
        }
        if ( isset( $in['erf_shield_idle_box'] ) ) {
            $cur['idle_on']   = empty( $in['idle_on'] ) ? 0 : 1;
            $cur['idle_mins'] = isset( $in['idle_mins'] ) ? max( 5, (int) $in['idle_mins'] ) : 60;
        }
        if ( isset( $in['erf_shield_api_box'] ) ) {
            $cur['app_pw_off'] = empty( $in['app_pw_off'] ) ? 0 : 1;
            $cur['rest_auth']  = empty( $in['rest_auth'] ) ? 0 : 1;
        }
        update_option( 'erf_shield_harden', $cur );
    }

    if ( ! empty( $_POST['erf_shield_logout_all'] ) && check_admin_referer( 'erf_shield_harden' ) ) {
        // Destroy every session token for every user, then require the current
        // admin to sign back in. Uses WP's own session manager, no tables.
        foreach ( get_users( array( 'fields' => array( 'ID' ) ) ) as $u ) {
            $mgr = WP_Session_Tokens::get_instance( $u->ID );
            $mgr->destroy_all();
        }
        if ( function_exists( 'erf_shield_log' ) ) { erf_shield_log( 'session', 'all sessions destroyed by admin' ); }
        wp_safe_redirect( wp_login_url() );
        exit;
    }
} );

add_action( 'erf_shield_page_sections', function () {
    $h = erf_shield_harden();
    ?>
    <div class="box">
      <h2>content security policy</h2>
      <form method="post">
        <?php wp_nonce_field( 'erf_shield_harden' ); ?>
        <input type="hidden" name="erf_shield_csp_box" value="1">
        <label><input type="checkbox" name="csp_on" <?php checked( ! empty( $h['csp_on'] ) ); ?>> send a Content-Security-Policy header on front-end responses (never on wp-admin)</label>
        <label><input type="checkbox" name="csp_report" <?php checked( ! empty( $h['csp_report'] ) ); ?>> report-only mode (test the policy without blocking anything, watch the browser console, then turn this off to enforce)</label>
        <p style="margin:10px 0 4px" class="muted">policy (edit with care; a wrong value can break the front end):</p>
        <textarea name="csp_value" rows="4" style="width:100%;font-family:ui-monospace,monospace;font-size:11.5px"><?php echo esc_textarea( $h['csp_value'] ); ?></textarea>
        <p style="margin-top:10px"><button class="button button-primary" name="erf_shield_harden_save" value="1">save</button></p>
      </form>
    </div>

    <div class="box">
      <h2>sessions</h2>
      <form method="post">
        <?php wp_nonce_field( 'erf_shield_harden' ); ?>
        <input type="hidden" name="erf_shield_idle_box" value="1">
        <label><input type="checkbox" name="idle_on" <?php checked( ! empty( $h['idle_on'] ) ); ?>> log a user out after
          <input type="number" name="idle_mins" value="<?php echo (int) $h['idle_mins']; ?>" min="5" max="1440" style="width:70px"> minutes of inactivity</label>
        <p style="margin-top:10px"><button class="button button-primary" name="erf_shield_harden_save" value="1">save</button></p>
      </form>
      <form method="post" style="margin-top:10px" onsubmit="return confirm('Log every user out of every device now? You will need to sign back in.');">
        <?php wp_nonce_field( 'erf_shield_harden' ); ?>
        <button class="button" name="erf_shield_logout_all" value="1" style="color:#b32d2e">log everyone out everywhere</button>
        <span class="muted" style="margin-left:8px">for the "I think I was phished" moment</span>
      </form>
    </div>

    <div class="box">
      <h2>api surface</h2>
      <form method="post">
        <?php wp_nonce_field( 'erf_shield_harden' ); ?>
        <input type="hidden" name="erf_shield_api_box" value="1">
        <label><input type="checkbox" name="app_pw_off" <?php checked( ! empty( $h['app_pw_off'] ) ); ?>> turn off application passwords (the wp-admin feature that mints standalone API tokens). leave on only if a service you use needs them.</label>
        <label><input type="checkbox" name="rest_auth" <?php checked( ! empty( $h['rest_auth'] ) ); ?>> require sign-in for the REST API (blocks anonymous reads). the block editor and logged-in tools are unaffected; turn on only if nothing public on the front end reads the REST API.</label>
        <p style="margin-top:10px"><button class="button button-primary" name="erf_shield_harden_save" value="1">save</button></p>
      </form>
    </div>
    <?php
} );
