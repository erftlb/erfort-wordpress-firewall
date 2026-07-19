<?php
/**
 * Uninstall cleanup for Erfort.
 *
 * Runs only when the plugin is DELETED (never on deactivate). Drops its options,
 * 2FA user meta, event log, and scheduled jobs. It deliberately LEAVES the
 * wp-content/shield-quarantine folder in place: it may hold files you moved there
 * and have not reviewed, and Erfort never deletes a file on its own.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) { exit; }

global $wpdb;

// Unschedule background jobs.
foreach ( array( 'erf_shield_integrity_cron', 'erf_shield_malware_cron', 'erf_shield_digest_cron' ) as $hook ) {
    wp_clear_scheduled_hook( $hook );
}

// Named options plus a namespace sweep.
$options = array(
    'erf_shield', 'erf_shield_log', 'erf_shield_off',
    'erf_shield_2fa', 'erf_shield_harden', 'erf_shield_audit', 'erf_shield_digest', 'erf_shield_digest_last',
    'erf_shield_integrity', 'erf_shield_integrity_result', 'erf_shield_integrity_plugins_result',
    'erf_shield_malware', 'erf_shield_malware_result', 'erf_shield_quarantine',
);
foreach ( $options as $o ) { delete_option( $o ); }
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'erf_shield\_%'" );

// Two-factor secrets and the last-seen stamps.
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '\_erf_2fa\_%' OR meta_key LIKE 'erf_shield_seen\_%'" );

// Transients (login buckets, alert throttles, plugin-checksum cache).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_erf_shield\_%' OR option_name LIKE '\_transient\_timeout\_erf_shield\_%'" );
