<?php
/**
 * Audit log + email alerts.
 *
 * The core plugin's log records security *events* (lockouts, probes). This adds
 * the admin *actions* that matter for accountability on a client site: who
 * signed in, who turned a plugin on or off, who changed a user's role, when a
 * new administrator appears, when the theme is switched. Everything is written
 * to the same Erfort event log (kind "audit"), so there is still one record and
 * no new storage.
 *
 * A handful of these are worth interrupting you for. When a NEW administrator is
 * created, or an existing user is promoted to administrator, Erfort emails the
 * site admin. That is the single most common sign of a takeover, and email is
 * not telemetry: it goes to you, carries only what happened, and calls no cloud.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

if ( ! function_exists( 'erf_shield_alert' ) ) {
    function erf_shield_alert( $subject, $body ) {
        $to = get_option( 'admin_email' );
        if ( ! $to ) { return; }
        $k = 'erf_shield_alert_' . md5( $subject );
        if ( get_transient( $k ) ) { return; }
        set_transient( $k, 1, 6 * HOUR_IN_SECONDS );
        wp_mail( $to, '[Erfort] ' . $subject . ' - ' . wp_parse_url( home_url(), PHP_URL_HOST ), $body );
    }
}

function erf_shield_audit_on() {
    $o = get_option( 'erf_shield_audit', array( 'enabled' => 1 ) );
    return ! empty( $o['enabled'] );
}

/** Log an audit line, attributing it to the current user when there is one. */
function erf_shield_audit( $detail ) {
    if ( ! function_exists( 'erf_shield_log' ) ) { return; }
    $who = '';
    $u   = wp_get_current_user();
    if ( $u && $u->exists() ) { $who = $u->user_login . ': '; }
    erf_shield_log( 'audit', $who . $detail );
}

/* -------- sign-ins -------- */
add_action( 'wp_login', function ( $login, $user ) {
    if ( ! erf_shield_audit_on() ) { return; }
    $roles = ( $user instanceof WP_User ) ? implode( '/', $user->roles ) : '';
    erf_shield_log( 'audit', 'login: ' . $login . ( $roles ? ' (' . $roles . ')' : '' ) );
}, 10, 2 );

/* -------- plugin on/off -------- */
add_action( 'activated_plugin', function ( $plugin ) {
    if ( erf_shield_audit_on() ) { erf_shield_audit( 'activated plugin ' . $plugin ); }
} );
add_action( 'deactivated_plugin', function ( $plugin ) {
    if ( erf_shield_audit_on() ) { erf_shield_audit( 'deactivated plugin ' . $plugin ); }
} );

/* -------- theme switch -------- */
add_action( 'switch_theme', function ( $name ) {
    if ( erf_shield_audit_on() ) { erf_shield_audit( 'switched theme to ' . $name ); }
} );

/* -------- new administrator created -------- */
add_action( 'user_register', function ( $user_id ) {
    if ( ! erf_shield_audit_on() ) { return; }
    $u = get_userdata( $user_id );
    if ( ! $u ) { return; }
    $is_admin = in_array( 'administrator', (array) $u->roles, true );
    erf_shield_audit( 'created user ' . $u->user_login . ' (' . implode( '/', $u->roles ) . ')' );
    if ( $is_admin ) {
        erf_shield_alert( 'a new administrator was created', 'A new administrator account was created on ' . home_url() . ":\n\nusername: " . $u->user_login . "\nemail: " . $u->user_email . "\n\nIf this was not you, treat the site as compromised: change all admin passwords, and review Users and Erfort's event log immediately." );
    }
} );

/* -------- role change to administrator -------- */
add_action( 'set_user_role', function ( $user_id, $role, $old_roles ) {
    if ( ! erf_shield_audit_on() ) { return; }
    $u = get_userdata( $user_id );
    $login = $u ? $u->user_login : ( '#' . $user_id );
    erf_shield_audit( 'set role of ' . $login . ' to ' . $role );
    if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) {
        erf_shield_alert( 'a user was promoted to administrator', 'User "' . $login . '" was just granted the administrator role on ' . home_url() . ".\n\nIf this was not you, treat the site as compromised and review Users and Erfort's event log." );
    }
}, 10, 3 );

/* -------- core / plugin auto or manual updates that change the version -------- */
add_action( 'upgrader_process_complete', function ( $upgrader, $data ) {
    if ( ! erf_shield_audit_on() || empty( $data['type'] ) ) { return; }
    $what = $data['type'] . ( ! empty( $data['action'] ) ? ' ' . $data['action'] : '' );
    erf_shield_audit( 'update ran: ' . $what );
}, 10, 2 );

/* -------- admin toggle -------- */
add_action( 'admin_init', function () {
    if ( ! is_admin() || empty( $_POST['erf_shield_audit_save'] ) ) { return; }
    if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'erf_shield_audit' ) ) { return; }
    update_option( 'erf_shield_audit', array( 'enabled' => empty( $_POST['erf_shield_audit_enabled'] ) ? 0 : 1 ) );
} );

add_action( 'erf_shield_page_sections', function () {
    $on = erf_shield_audit_on();
    ?>
    <div class="box">
      <h2>audit log &amp; alerts</h2>
      <form method="post">
        <?php wp_nonce_field( 'erf_shield_audit' ); ?>
        <label><input type="checkbox" name="erf_shield_audit_enabled" <?php checked( $on ); ?>> record admin actions (sign-ins, plugin on/off, theme switch, role changes, new users) into the event log, and email you when a new administrator is created or someone is promoted to administrator.</label>
        <p style="margin-top:10px"><button class="button button-primary" name="erf_shield_audit_save" value="1">save</button>
        <span class="muted" style="margin-left:12px">alerts go to <?php echo esc_html( get_option( 'admin_email' ) ); ?></span></p>
      </form>
    </div>
    <?php
} );
