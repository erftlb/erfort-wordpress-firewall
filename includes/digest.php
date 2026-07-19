<?php
/**
 * Weekly health digest.
 *
 * One scheduled email a week so the site tells you how it is doing instead of
 * waiting to be checked: pending core/plugin/theme updates, the latest core
 * integrity and malware scan verdicts, how many administrators exist, and how
 * much the log recorded in the last seven days (lockouts, probes, and friends).
 *
 * It collects nothing new, it only summarises what Erfort already records, and
 * it reuses erf_shield_alert()'s wp_mail. Off by default. Report only.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Shared alert helper (defined by whichever pro module loads first). */
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

function erf_shield_digest_on() {
    $o = get_option( 'erf_shield_digest', array( 'enabled' => 0 ) );
    return ! empty( $o['enabled'] );
}

/**
 * Assemble the digest. Returns array('body'=>string, 'lines'=>[], 'warnings'=>int)
 * so the same content feeds both the email and the on-screen preview.
 */
function erf_shield_digest_build() {
    $host     = wp_parse_url( home_url(), PHP_URL_HOST );
    $warnings = 0;
    $lines    = array();

    // Pending updates (core, plugins, themes).
    if ( ! function_exists( 'get_plugin_updates' ) ) {
        require_once ABSPATH . 'wp-admin/includes/update.php';
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $plugin_updates = function_exists( 'get_plugin_updates' ) ? count( get_plugin_updates() ) : 0;
    $theme_updates  = function_exists( 'get_theme_updates' ) ? count( get_theme_updates() ) : 0;
    $core_updates   = 0;
    if ( function_exists( 'get_core_updates' ) ) {
        foreach ( (array) get_core_updates() as $u ) {
            if ( isset( $u->response ) && 'upgrade' === $u->response ) { $core_updates++; }
        }
    }
    $pending = $core_updates + $plugin_updates + $theme_updates;
    if ( $pending > 0 ) { $warnings++; }
    $lines[] = 'Updates waiting: ' . ( $pending
        ? $pending . ' (' . $core_updates . ' core, ' . $plugin_updates . ' plugin, ' . $theme_updates . ' theme) - apply them'
        : 'none, everything current' );

    // Administrators.
    $admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'user_login' ) ) );
    if ( count( $admins ) > 2 ) { $warnings++; }
    $lines[] = 'Administrators: ' . count( $admins ) . ' (' . implode( ', ', wp_list_pluck( $admins, 'user_login' ) ) . ')';

    // Latest integrity scan.
    $integrity = get_option( 'erf_shield_integrity_result', array() );
    if ( ! empty( $integrity ) && empty( $integrity['error'] ) ) {
        $bad = count( (array) ( $integrity['modified'] ?? array() ) )
             + count( (array) ( $integrity['missing'] ?? array() ) )
             + count( (array) ( $integrity['unknown'] ?? array() ) );
        if ( $bad > 0 ) { $warnings++; }
        $lines[] = 'Core integrity: ' . ( $bad ? $bad . ' file issue(s), review in Erfort' : 'all core files match' )
            . ' (scanned ' . human_time_diff( (int) ( $integrity['time'] ?? time() ) ) . ' ago)';
    } else {
        $lines[] = 'Core integrity: no scan on record yet';
    }

    // Latest malware scan.
    $malware = get_option( 'erf_shield_malware_result', array() );
    if ( ! empty( $malware ) && empty( $malware['error'] ) ) {
        $flagged = count( (array) ( $malware['hits'] ?? array() ) );
        if ( $flagged > 0 ) { $warnings++; }
        $lines[] = 'Malware scan: ' . ( $flagged ? $flagged . ' file(s) flagged for review' : 'nothing flagged' )
            . ' (scanned ' . human_time_diff( (int) ( $malware['time'] ?? time() ) ) . ' ago)';
    } else {
        $lines[] = 'Malware scan: no scan on record yet';
    }

    // Log pressure over the last seven days.
    $log    = get_option( 'erf_shield_log', array() );
    $since  = time() - 7 * DAY_IN_SECONDS;
    $counts = array();
    foreach ( (array) $log as $e ) {
        if ( ! empty( $e['t'] ) && $e['t'] >= $since ) {
            $k            = $e['kind'] ?? '?';
            $counts[ $k ] = ( $counts[ $k ] ?? 0 ) + 1;
        }
    }
    if ( $counts ) {
        arsort( $counts );
        $parts = array();
        foreach ( $counts as $k => $n ) { $parts[] = $n . ' ' . $k; }
        $lines[] = 'Events (7 days): ' . implode( ', ', $parts );
    } else {
        $lines[] = 'Events (7 days): none recorded';
    }

    $body  = 'Weekly Erfort digest for ' . home_url() . "\n";
    $body .= str_repeat( '-', 48 ) . "\n\n";
    $body .= implode( "\n", $lines ) . "\n\n";
    $body .= ( $warnings
        ? $warnings . ' item(s) want your attention. Open Erfort in wp-admin to act.'
        : 'Nothing needs attention this week.' ) . "\n\n";
    $body .= 'Erfort does not change anything on its own. This is a report.';

    return array( 'body' => $body, 'lines' => $lines, 'warnings' => $warnings );
}

/** Send the digest now and remember when. */
function erf_shield_digest_send() {
    $d  = erf_shield_digest_build();
    $to = get_option( 'admin_email' );
    if ( $to ) {
        wp_mail( $to, '[Erfort] weekly digest - ' . wp_parse_url( home_url(), PHP_URL_HOST ), $d['body'] );
    }
    update_option( 'erf_shield_digest_last', time(), false );
    return $d;
}

/* schedule weekly while enabled; clear the schedule when switched off */
add_action( 'erf_shield_digest_cron', function () { if ( erf_shield_digest_on() ) { erf_shield_digest_send(); } } );
add_action( 'init', function () {
    $scheduled = (bool) wp_next_scheduled( 'erf_shield_digest_cron' );
    if ( erf_shield_digest_on() && ! $scheduled ) {
        wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly', 'erf_shield_digest_cron' );
    } elseif ( ! erf_shield_digest_on() && $scheduled ) {
        wp_clear_scheduled_hook( 'erf_shield_digest_cron' );
    }
} );

/* admin: toggle + send-now + last-sent + live preview */
add_action( 'admin_init', function () {
    if ( ! is_admin() ) { return; }
    if ( ! empty( $_POST['erf_shield_digest_save'] ) && current_user_can( 'manage_options' ) && check_admin_referer( 'erf_shield_digest' ) ) {
        update_option( 'erf_shield_digest', array( 'enabled' => empty( $_POST['erf_shield_digest_enabled'] ) ? 0 : 1 ) );
    }
    if ( ! empty( $_POST['erf_shield_digest_send'] ) && current_user_can( 'manage_options' ) && check_admin_referer( 'erf_shield_digest' ) ) {
        erf_shield_digest_send();
    }
} );

add_action( 'erf_shield_page_sections', function () {
    $on   = erf_shield_digest_on();
    $last = (int) get_option( 'erf_shield_digest_last', 0 );
    $d    = erf_shield_digest_build();
    ?>
    <div class="box">
      <h2>weekly digest</h2>
      <form method="post">
        <?php wp_nonce_field( 'erf_shield_digest' ); ?>
        <label><input type="checkbox" name="erf_shield_digest_enabled" <?php checked( $on ); ?>> email a one-page health summary to the site admin (<?php echo esc_html( get_option( 'admin_email' ) ); ?>) once a week: pending updates, integrity and malware verdicts, admin count, and the week's event volume. report only.</label>
        <p style="margin-top:10px">
          <button class="button button-primary" name="erf_shield_digest_save" value="1">save</button>
          <button class="button" name="erf_shield_digest_send" value="1">send now</button>
          <?php if ( $last ) : ?><span class="muted" style="margin-left:8px">last sent <?php echo esc_html( human_time_diff( $last ) ); ?> ago</span><?php endif; ?>
        </p>
      </form>
      <table style="margin-top:12px">
        <tr><td style="width:170px">this week</td>
            <td class="<?php echo $d['warnings'] ? 'warn' : 'ok'; ?>"><?php echo $d['warnings'] ? esc_html( $d['warnings'] . ' item(s) want attention' ) : 'nothing needs attention'; ?></td></tr>
        <?php foreach ( $d['lines'] as $line ) : ?>
          <tr class="logrow"><td class="muted">·</td><td><?php echo esc_html( $line ); ?></td></tr>
        <?php endforeach; ?>
      </table>
    </div>
    <?php
} );
