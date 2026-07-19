<?php
/**
 * Plugin Name: Erfort
 * Plugin URI:  https://erf.studio
 * Description: A small, honest firewall for the sites Erf builds. Login rate limiting, probe blocking, xmlrpc off, user enumeration off, security headers, a plain health report. Deterministic, no cloud, nothing phones home by default (the optional self-hosted update checker is the one exception, and only if you point it at your own manifest).
 * Version:     1.5.1
 * Author:      Erf Talebi
 * Author URI:  https://erf.studio
 *
 * Copyright (c) 2026 Erfan Talebi ("Erf Talebi"). Developed and commissioned by Erf Talebi for Erf Studio.
 *
 * Publicly named Erfort - "Shield" collided with an existing, well-known
 * WordPress security plugin (Shield Security / getshieldsecurity.com, 30k+
 * installs), so the public release needed a name of its own. The
 * erf_shield_ function prefix and erf-shield file/folder slug stay
 * unchanged: they're a collision guard for the code, not the brand, and
 * renaming live functions across every site already running this buys
 * nothing but risk.
 *
 * THE THREAT MODEL, so nobody bolts features onto this without thinking:
 * these are portfolio, nonprofit and small-business sites on shared hosting.
 * What actually arrives is bot login stuffing, scanners probing known plugin
 * holes, user enumeration to feed the stuffing, and xmlrpc amplification.
 * What does not arrive is a targeted attacker, so there is no regex WAF, no
 * signature scanner, no "military grade" anything. Every protection here is
 * cheap, deterministic, and safe to leave on. One file, so dropping it into
 * a new site is the whole install.
 *
 * No em dashes anywhere.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'ERF_SHIELD_VERSION', '1.5.1' );
define( 'ERF_SHIELD_PATH', plugin_dir_path( __FILE__ ) );
define( 'ERF_SHIELD_URL', plugin_dir_url( __FILE__ ) );

/* The pro layer. The original single-file core above (login guard, probes,
 * xmlrpc, enum, headers, editors, version cloak, health, log) stays exactly as
 * it was; these add-ons live in their own files and each carries its own
 * option + save handler + admin section, so the core is never touched. The
 * whole install is still "copy the folder". Guarded so a partial copy cannot
 * fatal the site. */
foreach ( array( 'admin-ui', 'twofactor', 'integrity', 'malware', 'audit', 'hardening', 'digest', 'updater' ) as $erf_shield_mod ) {
    $erf_shield_file = ERF_SHIELD_PATH . 'includes/' . $erf_shield_mod . '.php';
    if ( file_exists( $erf_shield_file ) ) { require_once $erf_shield_file; }
}
unset( $erf_shield_mod, $erf_shield_file );

/* ---------------------------------------------------------------- settings */

function erf_shield_defaults() {
    return array(
        'login_guard'   => 1,  // rate-limit failed logins per IP and per username
        'probe_block'   => 1,  // 403 the classic scanner paths before WP routes them
        'xmlrpc_off'    => 1,  // xmlrpc.php answers 403; pingbacks gone with it
        'enum_off'      => 1,  // no ?author= redirects, no anonymous REST user list
        'headers_on'    => 1,  // the boring, correct security headers
        'editors_off'   => 1,  // wp-admin file editors gone (updates unaffected)
        'cloak_version' => 1,  // no generator tag
    );
}

function erf_shield_opt( $key ) {
    static $opts = null;
    if ( null === $opts ) { $opts = wp_parse_args( get_option( 'erf_shield', array() ), erf_shield_defaults() ); }
    return ! empty( $opts[ $key ] );
}

/**
 * Break glass. When ERF_SHIELD_OFF is defined truthy in wp-config.php, or the
 * erf_shield_off flag is set (via `wp shield off`), every protection that can
 * lock a person out (the login guard, two-factor, and idle logout) stand
 * down so an administrator can get back in. The passive protections (probe
 * block, headers, version cloak) are unaffected; they never lock anyone out.
 * Turn it back on the moment you are in: `wp shield on`, or remove the constant.
 */
function erf_shield_off() {
    return ( defined( 'ERF_SHIELD_OFF' ) && ERF_SHIELD_OFF ) || (bool) get_option( 'erf_shield_off' );
}

register_activation_hook( __FILE__, function () {
    add_option( 'erf_shield', erf_shield_defaults() );
    add_option( 'erf_shield_log', array(), '', 'no' );   // ring buffer, never autoloaded
} );

/* ------------------------------------------------------------------ helpers */

/** Cloudflare's published edge IP ranges. Source: https://www.cloudflare.com/ips/
 * (https://www.cloudflare.com/ips-v4 and /ips-v6). Refresh occasionally; CF adds
 * ranges rarely. Used to decide whether the CF-Connecting-IP header can be
 * trusted, i.e. whether the request actually reached us through Cloudflare. */
function erf_shield_cf_ranges() {
    return array(
        // IPv4
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        // IPv6
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    );
}

/** IPv4 CIDR membership. */
function erf_shield_v4_in_cidr( $ip, $cidr ) {
    $parts = explode( '/', $cidr );
    if ( 2 !== count( $parts ) ) { return false; }
    $ip_long     = ip2long( $ip );
    $subnet_long = ip2long( $parts[0] );
    if ( false === $ip_long || false === $subnet_long ) { return false; }
    $bits = (int) $parts[1];
    if ( $bits <= 0 ) { return true; }
    $mask = -1 << ( 32 - $bits );
    return ( $ip_long & $mask ) === ( $subnet_long & $mask );
}

/** IPv6 CIDR membership, by comparing the packed bytes up to the prefix length. */
function erf_shield_v6_in_cidr( $ip, $cidr ) {
    $parts = explode( '/', $cidr );
    if ( 2 !== count( $parts ) ) { return false; }
    $ip_bin     = @inet_pton( $ip );
    $subnet_bin = @inet_pton( $parts[0] );
    if ( false === $ip_bin || false === $subnet_bin || 16 !== strlen( $ip_bin ) || 16 !== strlen( $subnet_bin ) ) { return false; }
    $bits  = (int) $parts[1];
    $bytes = intdiv( $bits, 8 );
    $rem   = $bits % 8;
    if ( $bytes > 0 && 0 !== substr_compare( $ip_bin, $subnet_bin, 0, $bytes ) ) { return false; }
    if ( $rem > 0 ) {
        $mask = chr( ( 0xff << ( 8 - $rem ) ) & 0xff );
        if ( ( $ip_bin[ $bytes ] & $mask ) !== ( $subnet_bin[ $bytes ] & $mask ) ) { return false; }
    }
    return true;
}

/** True when $remote (the real connecting address) is a Cloudflare edge IP. */
function erf_shield_is_cf( $remote ) {
    if ( '' === $remote || false === filter_var( $remote, FILTER_VALIDATE_IP ) ) { return false; }
    $is_v6 = ( false !== strpos( $remote, ':' ) );
    foreach ( erf_shield_cf_ranges() as $cidr ) {
        $range_v6 = ( false !== strpos( $cidr, ':' ) );
        if ( $is_v6 !== $range_v6 ) { continue; }
        if ( $is_v6 ? erf_shield_v6_in_cidr( $remote, $cidr ) : erf_shield_v4_in_cidr( $remote, $cidr ) ) {
            return true;
        }
    }
    return false;
}

/** the visitor's IP. REMOTE_ADDR is set by the web server and cannot be spoofed
 * by the client. The CF-Connecting-IP header is trusted ONLY when the request
 * actually arrived through Cloudflare, i.e. REMOTE_ADDR is a published CF edge
 * address; otherwise anyone could forge the header to evade the per-IP limit or
 * frame a victim's IP into a lockout. Any header value is IP-validated first. */
function erf_shield_ip() {
    $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
    if ( erf_shield_is_cf( $remote ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
        $cf = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        if ( false !== filter_var( $cf, FILTER_VALIDATE_IP ) ) {
            return $cf;
        }
    }
    return $remote;
}

/** append one line to the ring buffer. Newest first, capped, autoload off. */
function erf_shield_log( $kind, $detail ) {
    $log = get_option( 'erf_shield_log', array() );
    array_unshift( $log, array(
        't'    => time(),
        'kind' => $kind,
        'ip'   => erf_shield_ip(),
        'd'    => mb_substr( $detail, 0, 200 ),
    ) );
    if ( count( $log ) > 200 ) { $log = array_slice( $log, 0, 200 ); }
    update_option( 'erf_shield_log', $log, 'no' );
}

/* -------------------------------------------------------------- login guard
 * Five failures in fifteen minutes locks the pair (IP, and separately the
 * username) for fifteen minutes. Transients, so it needs no table and it
 * heals itself. The login error goes generic so the form stops confirming
 * which usernames exist. */

const ERF_SHIELD_FAILS  = 5;
const ERF_SHIELD_WINDOW = 900;

function erf_shield_bucket( $key ) { return 'erf_shield_' . md5( $key ); }

function erf_shield_locked( $key ) {
    $b = get_transient( erf_shield_bucket( $key ) );
    return is_array( $b ) && count( $b ) >= ERF_SHIELD_FAILS;
}

function erf_shield_record_fail( $key ) {
    $id  = erf_shield_bucket( $key );
    $b   = get_transient( $id );
    $b   = is_array( $b ) ? $b : array();
    $now = time();
    $b   = array_values( array_filter( $b, function ( $t ) use ( $now ) { return $t > $now - ERF_SHIELD_WINDOW; } ) );
    $b[] = $now;
    set_transient( $id, $b, ERF_SHIELD_WINDOW );
    return count( $b );
}

/* Priority 30 is deliberate, DO NOT lower it. Core's wp_authenticate_username_password
 * runs on 'authenticate' at priority 20 and, when real credentials are present,
 * ignores any WP_Error a lower-priority filter returned and overwrites it with the
 * authenticated WP_User (see WP core / Trac #52439). Running at 5 meant our lockout
 * only changed the error message: a correct password during a lockout still logged
 * in. Running LAST, our WP_Error vetoes core's result and the login is truly blocked.
 * When NOT locked we return $user untouched (the exact value we were handed, which at
 * priority 30 is core's authenticated WP_User or its WP_Error), so normal logins are
 * unaffected. Never return null here: at this priority null would blank out a valid
 * login and break all sign-ins. */
add_filter( 'authenticate', function ( $user, $username ) {
    if ( erf_shield_off() || ! erf_shield_opt( 'login_guard' ) || '' === (string) $username ) { return $user; }
    if ( erf_shield_locked( 'ip_' . erf_shield_ip() ) || erf_shield_locked( 'user_' . strtolower( $username ) ) ) {
        return new WP_Error( 'erf_shield_locked', __( 'Too many attempts. Try again in a few minutes.' ) );
    }
    return $user;
}, 30, 2 );

add_action( 'wp_login_failed', function ( $username ) {
    if ( ! erf_shield_opt( 'login_guard' ) ) { return; }
    $n = erf_shield_record_fail( 'ip_' . erf_shield_ip() );
    erf_shield_record_fail( 'user_' . strtolower( (string) $username ) );
    if ( $n >= ERF_SHIELD_FAILS ) {
        erf_shield_log( 'lockout', 'login lockout after ' . $n . ' fails, user: ' . $username );
    }
} );

add_action( 'wp_login', function ( $username ) {
    delete_transient( erf_shield_bucket( 'ip_' . erf_shield_ip() ) );
    delete_transient( erf_shield_bucket( 'user_' . strtolower( (string) $username ) ) );
}, 10, 1 );

/* wrong password and unknown user read identically now */
add_filter( 'login_errors', function ( $error ) {
    if ( ! erf_shield_opt( 'login_guard' ) ) { return $error; }
    if ( false !== strpos( $error, 'erf_shield_locked' ) || false !== strpos( $error, 'Too many attempts' ) ) { return $error; }
    return __( 'The credentials do not match.' );
} );

/* -------------------------------------------------------- registration guard
 * Only relevant when the site allows sign-ups (Kit optional accounts). A
 * honeypot field bots fill and humans never see, plus a per-IP rate limit, so
 * open registration cannot be scripted into a spam-account flood. The email
 * verification WordPress already does (the set-password link) is the second
 * wall: an account needs a live inbox to become usable. */

add_action( 'register_form', function () {
    if ( ! erf_shield_opt( 'login_guard' ) ) { return; }
    echo '<p style="position:absolute;left:-9999px" aria-hidden="true">'
        . '<label>Leave this empty<input type="text" name="erf_shield_hp" tabindex="-1" autocomplete="off"></label></p>';
} );

add_filter( 'registration_errors', function ( $errors ) {
    if ( ! erf_shield_opt( 'login_guard' ) ) { return $errors; }
    if ( ! empty( $_POST['erf_shield_hp'] ) ) {              // a bot filled the trap
        erf_shield_log( 'register', 'honeypot tripped' );
        $errors->add( 'erf_shield_bot', __( 'Registration could not be completed.' ) );
        return $errors;
    }
    // five sign-ups per IP per fifteen minutes (the shared lock window)
    $key = 'reg_' . erf_shield_ip();
    if ( erf_shield_locked( $key ) ) {
        $errors->add( 'erf_shield_reg_rate', __( 'Too many sign-ups from here. Try again in a few minutes.' ) );
        return $errors;
    }
    $n = erf_shield_record_fail( $key );
    if ( $n >= ERF_SHIELD_FAILS ) { erf_shield_log( 'register', 'rate limit hit' ); }
    return $errors;
}, 20 );

/* --------------------------------------------------------------- probe block
 * The fixed list of things scanners ask every WordPress site for. A request
 * for any of these is never legitimate on these sites, so it ends here, one
 * cheap strpos sweep, before WP builds a query for it. Deliberately a LIST,
 * not a pattern language: a list cannot false-positive on a real page. */

add_action( 'plugins_loaded', function () {
    if ( ! erf_shield_opt( 'probe_block' ) || empty( $_SERVER['REQUEST_URI'] ) ) { return; }
    $uri    = strtolower( rawurldecode( (string) wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
    $probes = array(
        '.env', 'wp-config.php.', 'wp-config.bak', 'wp-config.old', 'wp-config.save',
        '.git/', '.svn/', '.DS_Store', 'phpunit', 'eval-stdin.php', 'phpinfo.php',
        'wp-content/debug.log', '.sql', 'dump.sql', 'backup.zip', 'adminer',
        'wlwmanifest.xml', 'xmlrpc.php?rsd',
    );
    foreach ( $probes as $p ) {
        if ( false !== strpos( $uri, strtolower( $p ) ) ) {
            erf_shield_log( 'probe', $uri );
            status_header( 403 );
            nocache_headers();
            exit;
        }
    }
}, 1 );

/* -------------------------------------------------------------------- xmlrpc */

add_filter( 'xmlrpc_enabled', function ( $on ) { return erf_shield_opt( 'xmlrpc_off' ) ? false : $on; } );
add_filter( 'wp_headers', function ( $headers ) {
    if ( erf_shield_opt( 'xmlrpc_off' ) ) { unset( $headers['X-Pingback'] ); }
    return $headers;
} );
add_action( 'init', function () {
    if ( ! erf_shield_opt( 'xmlrpc_off' ) ) { return; }
    if ( ! empty( $_SERVER['REQUEST_URI'] ) && false !== stripos( (string) wp_unslash( $_SERVER['REQUEST_URI'] ), 'xmlrpc.php' ) ) {
        erf_shield_log( 'xmlrpc', 'blocked' );
        status_header( 403 );
        exit;
    }
}, 1 );

/* -------------------------------------------------------- user enumeration */

add_action( 'template_redirect', function () {
    if ( ! erf_shield_opt( 'enum_off' ) || is_user_logged_in() ) { return; }
    // ?author=N redirects to /author/name/ and hands out every username
    if ( isset( $_GET['author'] ) ) {
        erf_shield_log( 'enum', '?author= probe' );
        wp_die( __( 'Not available.' ), 403 );
    }
}, 1 );

add_filter( 'rest_endpoints', function ( $endpoints ) {
    if ( ! erf_shield_opt( 'enum_off' ) || is_user_logged_in() ) { return $endpoints; }
    unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
    return $endpoints;
} );

/* ------------------------------------------------------------------ headers */

add_action( 'send_headers', function () {
    if ( ! erf_shield_opt( 'headers_on' ) || is_admin() ) { return; }
    header( 'X-Frame-Options: SAMEORIGIN' );
    header( 'X-Content-Type-Options: nosniff' );
    header( 'Referrer-Policy: strict-origin-when-cross-origin' );
    header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
} );

/* --------------------------------------------------------- file editors off
 * Capability filter, not a constant: DISALLOW_FILE_EDIT cannot be defined this
 * late, and file_mod_allowed would break updates. This removes exactly the
 * three editor capabilities and nothing else. */

add_filter( 'user_has_cap', function ( $caps ) {
    if ( erf_shield_opt( 'editors_off' ) ) {
        $caps['edit_files'] = false; $caps['edit_plugins'] = false; $caps['edit_themes'] = false;
    }
    return $caps;
} );

/* ------------------------------------------------------------ version cloak */

add_action( 'init', function () {
    if ( ! erf_shield_opt( 'cloak_version' ) ) { return; }
    remove_action( 'wp_head', 'wp_generator' );
    add_filter( 'the_generator', '__return_empty_string' );
} );

/* ------------------------------------------------------------- admin screen
 * One page under Settings: toggles, a plain health report, the event log.
 * Monochrome, mono type, no dashboards, no scores, no upsells. */

add_action( 'admin_menu', function () {
    $svg  = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="black" d="M10 1 3 4v5c0 4 3 7.2 7 9 4-1.8 7-5 7-9V4l-7-3zm0 2.2 5 2.1V9c0 3-2.2 5.6-5 7-2.8-1.4-5-4-5-7V5.3l5-2.1z"/></svg>';
    $icon = 'data:image/svg+xml;base64,' . base64_encode( $svg );
    add_menu_page( 'Erfort', 'Erfort', 'manage_options', 'erf-shield', 'erf_shield_page', $icon, 81 );

    /* Register the panel as its own first submenu. WordPress points a
     * top-level menu at its FIRST submenu item, so without this the "Erfort"
     * link would jump straight to whichever add-on registered a submenu first
     * (Fleet) instead of to Erfort's own panel. Only matters when at least one
     * submenu exists, but it costs nothing and keeps the parent honest. */
    add_submenu_page( 'erf-shield', 'Erfort', 'Erfort', 'manage_options', 'erf-shield', 'erf_shield_page' );
} );

add_action( 'admin_enqueue_scripts', function ( $hook ) {
    if ( 'toplevel_page_erf-shield' === $hook ) { erf_admin_enqueue( ERF_SHIELD_URL . 'assets', ERF_SHIELD_VERSION ); }
} );

function erf_shield_health() {
    global $wp_version, $wpdb;
    $rows   = array();
    $updates = function_exists( 'get_plugin_updates' ) ? count( get_plugin_updates() ) : 0;
    if ( ! function_exists( 'get_plugin_updates' ) ) { require_once ABSPATH . 'wp-admin/includes/update.php'; require_once ABSPATH . 'wp-admin/includes/plugin.php'; $updates = count( get_plugin_updates() ); }
    $rows[] = array( 'https', is_ssl(), is_ssl() ? 'on' : 'THE SITE IS NOT ON HTTPS' );
    $rows[] = array( 'php', version_compare( PHP_VERSION, '8.0', '>=' ), 'php ' . PHP_VERSION . ( version_compare( PHP_VERSION, '8.0', '>=' ) ? '' : ', end of life, ask the host to raise it' ) );
    $rows[] = array( 'plugin updates', 0 === $updates, $updates ? $updates . ' plugin(s) waiting for an update, update them' : 'everything current' );
    $rows[] = array( 'user "admin"', ! username_exists( 'admin' ), username_exists( 'admin' ) ? 'a user literally named admin exists, rename it' : 'no user named admin' );
    $rows[] = array( 'debug display', ! ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ), ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) ? 'WP_DEBUG_DISPLAY is on, errors print to visitors' : 'off' );
    $rows[] = array( 'table prefix', 'wp_' !== $wpdb->prefix, 'wp_' === $wpdb->prefix ? 'default wp_ prefix (fine, informational only)' : $wpdb->prefix );
    $admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'user_login' ) ) );
    $rows[] = array( 'administrators', count( $admins ) <= 2, implode( ', ', wp_list_pluck( $admins, 'user_login' ) ) );
    return $rows;
}

/* Stream the event log as CSV for a client handover. Runs on admin_init so the
 * headers are sent before any page HTML. Reuses the events form's nonce. */
add_action( 'admin_init', function () {
    if ( empty( $_POST['erf_shield_export_log'] ) ) { return; }
    if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'erf_shield_save' ) ) { return; }
    $log = get_option( 'erf_shield_log', array() );
    nocache_headers();
    header( 'Content-Type: text/csv; charset=utf-8' );
    header( 'Content-Disposition: attachment; filename="shield-log-' . gmdate( 'Ymd-His' ) . '.csv"' );
    $out = fopen( 'php://output', 'w' );
    fputcsv( $out, array( 'time_utc', 'kind', 'ip', 'detail' ) );
    foreach ( (array) $log as $e ) {
        fputcsv( $out, array( gmdate( 'Y-m-d H:i:s', (int) ( $e['t'] ?? 0 ) ), $e['kind'] ?? '', $e['ip'] ?? '', $e['d'] ?? '' ) );
    }
    fclose( $out );
    exit;
} );

function erf_shield_page() {
    if ( ! current_user_can( 'manage_options' ) ) { return; }
    if ( isset( $_POST['erf_shield_save'] ) && check_admin_referer( 'erf_shield_save' ) ) {
        $new = array();
        foreach ( array_keys( erf_shield_defaults() ) as $k ) { $new[ $k ] = empty( $_POST[ $k ] ) ? 0 : 1; }
        update_option( 'erf_shield', $new );
        echo '<div class="updated"><p>Saved.</p></div>';
    }
    if ( isset( $_POST['erf_shield_clearlog'] ) && check_admin_referer( 'erf_shield_save' ) ) {
        update_option( 'erf_shield_log', array(), 'no' );
    }
    $o      = wp_parse_args( get_option( 'erf_shield', array() ), erf_shield_defaults() );
    $labels = array(
        'login_guard'   => 'login guard: five failed attempts in fifteen minutes locks that IP and that username out for fifteen minutes',
        'probe_block'   => 'probe block: the fixed list of scanner paths (.env, wp-config backups, .git, adminer and friends) answers 403',
        'xmlrpc_off'    => 'xmlrpc off: the whole legacy endpoint answers 403, pingbacks included',
        'enum_off'      => 'enumeration off: no ?author= username leaks, no anonymous REST user list',
        'headers_on'    => 'security headers: frame, sniff, referrer and permissions policies on every front-end response',
        'editors_off'   => 'file editors off: the wp-admin plugin and theme editors are gone, updates still work',
        'cloak_version' => 'version cloak: no WordPress generator tag in the page head',
    );
    ?>
    <style>
      .erfsh{max-width:860px;font-family:ui-monospace,Menlo,Consolas,monospace}
      .erfsh h1{font-weight:600;letter-spacing:.02em}
      .erfsh .box{background:#fff;border:1px solid #c3c4c7;padding:16px 18px;margin:14px 0}
      .erfsh label{display:block;padding:7px 0;border-bottom:1px solid #eee;font-size:12.5px}
      .erfsh label:last-child{border-bottom:0}
      .erfsh input[type=checkbox]{margin-right:9px}
      .erfsh table{width:100%;border-collapse:collapse;font-size:12.5px}
      .erfsh td{padding:6px 8px;border-bottom:1px solid #eee;vertical-align:top}
      .erfsh .ok{color:#1a7a3c}.erfsh .warn{color:#b32d2e;font-weight:600}
      .erfsh .muted{color:#777}
      .erfsh .logrow td{font-size:11.5px}
    </style>
    <div class="wrap erfsh">
      <?php erf_admin_topbar( 'SHIELD', ERF_SHIELD_VERSION, 'developed by Erf Talebi', 'one-file firewall · Erf Studio' ); ?>
      <p class="muted">deterministic protections against the attacks that actually arrive. no cloud, nothing phones home by default, the log below is the only record kept.</p>

      <form method="post">
        <?php wp_nonce_field( 'erf_shield_save' ); ?>
        <div class="box">
          <?php foreach ( $labels as $k => $text ) : ?>
            <label><input type="checkbox" name="<?php echo esc_attr( $k ); ?>" <?php checked( ! empty( $o[ $k ] ) ); ?>><?php echo esc_html( $text ); ?></label>
          <?php endforeach; ?>
        </div>
        <p><button class="button button-primary" name="erf_shield_save" value="1">save</button></p>
      </form>

      <div class="box">
        <h2>health</h2>
        <table>
          <?php foreach ( erf_shield_health() as $row ) : ?>
            <tr><td style="width:170px"><?php echo esc_html( $row[0] ); ?></td>
                <td class="<?php echo $row[1] ? 'ok' : 'warn'; ?>"><?php echo esc_html( $row[2] ); ?></td></tr>
          <?php endforeach; ?>
        </table>
      </div>

      <div class="box">
        <h2>events <span class="muted">(newest first, last 200 kept)</span></h2>
        <table>
          <?php $log = get_option( 'erf_shield_log', array() ); if ( empty( $log ) ) : ?>
            <tr><td class="muted">nothing yet. quiet is good.</td></tr>
          <?php else : foreach ( $log as $e ) : ?>
            <tr class="logrow">
              <td style="width:150px"><?php echo esc_html( gmdate( 'Y-m-d H:i', $e['t'] ) ); ?></td>
              <td style="width:80px"><?php echo esc_html( $e['kind'] ); ?></td>
              <td style="width:130px"><?php echo esc_html( $e['ip'] ); ?></td>
              <td><?php echo esc_html( $e['d'] ); ?></td>
            </tr>
          <?php endforeach; endif; ?>
        </table>
        <form method="post" style="margin-top:10px"><?php wp_nonce_field( 'erf_shield_save' ); ?>
          <button class="button" name="erf_shield_clearlog" value="1">clear log</button>
          <button class="button" name="erf_shield_export_log" value="1">export csv</button>
        </form>
      </div>

      <?php do_action( 'erf_shield_page_sections' ); // pro modules render their boxes here ?>

      <?php erf_admin_credit( 'Erfort · an Erf Studio tool, developed and commissioned by Erf Talebi.' ); ?>
    </div>
    <?php
}

/* ------------------------------------------------------------------ wp-cli
 * Break-glass from the shell when you cannot reach wp-admin:
 *   wp erfort off      stand every lockout protection down
 *   wp erfort on       restore them
 *   wp erfort status   show the current state
 * The wp-config constant ERF_SHIELD_OFF does the same thing durably, for when
 * even the database is not cooperating. (The constant keeps its erf_shield_
 * internal name - see the docblock at the top of this file for why.) */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
    class Erf_Shield_CLI {
        /** Stand the login guard, two-factor, and idle logout down (break glass). */
        public function off() {
            update_option( 'erf_shield_off', 1 );
            WP_CLI::success( 'Erfort enforcement OFF: login guard, two-factor, and idle logout stood down. Run `wp erfort on` once you are back in.' );
        }
        /** Restore the lockout protections. */
        public function on() {
            delete_option( 'erf_shield_off' );
            WP_CLI::success( 'Erfort enforcement ON.' );
        }
        /** Report whether break glass is active. */
        public function status() {
            $const = defined( 'ERF_SHIELD_OFF' ) && ERF_SHIELD_OFF;
            WP_CLI::line( erf_shield_off()
                ? 'OFF, break glass active' . ( $const ? ' (via ERF_SHIELD_OFF constant)' : ' (via `wp erfort off`)' )
                : 'ON, all protections enforced' );
        }
    }
    WP_CLI::add_command( 'erfort', 'Erf_Shield_CLI' );
}
