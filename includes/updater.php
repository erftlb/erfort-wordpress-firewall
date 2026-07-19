<?php
/**
 * Self-hosted update client.
 *
 * The problem this fixes: these in-house plugins are copied to a dozen client
 * sites by hand, so old copies drift out of date (Erfort on the client builds
 * has already fallen behind). WordPress can only auto-update plugins it knows
 * from wordpress.org, and these are not there.
 *
 * So Erfort teaches WordPress to check a manifest hosted on erf.studio (infra
 * Erf controls, no GitHub, no third party): a small JSON file per plugin listing
 * the latest version and a download URL. When the manifest version beats the
 * installed one, the plugin shows an update in the normal Plugins screen and
 * one-click updates like anything else.
 *
 * The identical client ships inside every Erf plugin; the function is defined
 * once (guarded) and each plugin registers itself with its own config.
 *
 * Fleet check-in: right after a FRESH manifest fetch (i.e. once per ~6h cache
 * window, never on every admin page load), the site also posts its own url +
 * installed version to erf.studio's erf-fleet/v1/checkin endpoint. This is the
 * one deliberate exception to "nothing phones home": a site running this
 * updater has already opted into talking to erf.studio for updates, and the
 * check-in rides the same request cycle rather than adding a new one. Nothing
 * beyond url/slug/name/version is sent. Opt out per site with
 * define('ERF_FLEET_NO_CHECKIN', true) in wp-config.php.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

if ( ! function_exists( 'erf_updater_boot' ) ) {
    /**
     * @param array $cfg slug, name, version, basename, manifest (URL)
     */
    function erf_updater_boot( $cfg ) {
        $cfg = wp_parse_args( $cfg, array( 'slug' => '', 'name' => '', 'version' => '0', 'basename' => '', 'manifest' => '' ) );
        if ( '' === $cfg['slug'] || '' === $cfg['manifest'] ) { return; }

        $cache_key = 'erf_upd_' . md5( $cfg['manifest'] );

        // Fetch + cache the manifest (6h) so we do not hit the network on every
        // admin page load. Returns the decoded object or null.
        $get_manifest = function () use ( $cfg, $cache_key ) {
            $cached = get_transient( $cache_key );
            if ( is_array( $cached ) ) { return $cached; }
            $res = wp_remote_get( $cfg['manifest'], array( 'timeout' => 6, 'headers' => array( 'Accept' => 'application/json' ) ) );
            if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
                set_transient( $cache_key, array(), HOUR_IN_SECONDS ); // brief negative cache
                return null;
            }
            $data = json_decode( wp_remote_retrieve_body( $res ), true );
            if ( ! is_array( $data ) || empty( $data['version'] ) ) { return null; }
            set_transient( $cache_key, $data, 6 * HOUR_IN_SECONDS );

            if ( ! ( defined( 'ERF_FLEET_NO_CHECKIN' ) && ERF_FLEET_NO_CHECKIN ) ) {
                wp_remote_post( 'https://erf.studio/wp-json/erf-fleet/v1/checkin', array(
                    'timeout'  => 3,
                    'blocking' => false,
                    'body'     => array(
                        'site'    => home_url(),
                        'slug'    => $cfg['slug'],
                        'name'    => $cfg['name'],
                        'version' => $cfg['version'],
                    ),
                ) );
            }

            return $data;
        };

        // Inject an available update into the core update list.
        add_filter( 'pre_set_site_transient_update_plugins', function ( $transient ) use ( $cfg, $get_manifest ) {
            if ( ! is_object( $transient ) ) { return $transient; }
            $m = $get_manifest();
            if ( ! $m ) { return $transient; }
            if ( version_compare( $cfg['version'], $m['version'], '>=' ) ) {
                // Up to date: make sure we are not stuck in the response list.
                if ( isset( $transient->response[ $cfg['basename'] ] ) ) { unset( $transient->response[ $cfg['basename'] ] ); }
                return $transient;
            }
            $obj = (object) array(
                'slug'        => $cfg['slug'],
                'plugin'      => $cfg['basename'],
                'new_version' => $m['version'],
                'url'         => $m['homepage'] ?? 'https://erf.studio',
                'package'     => $m['download_url'] ?? '',
                'tested'      => $m['tested'] ?? '',
                'requires'    => $m['requires'] ?? '',
                'icons'       => array(),
            );
            $transient->response[ $cfg['basename'] ] = $obj;
            return $transient;
        } );

        // Provide the "View details" popup content.
        add_filter( 'plugins_api', function ( $result, $action, $args ) use ( $cfg, $get_manifest ) {
            if ( 'plugin_information' !== $action || empty( $args->slug ) || $args->slug !== $cfg['slug'] ) { return $result; }
            $m = $get_manifest();
            if ( ! $m ) { return $result; }
            return (object) array(
                'name'          => $cfg['name'] !== '' ? $cfg['name'] : $m['name'] ?? $cfg['slug'],
                'slug'          => $cfg['slug'],
                'version'       => $m['version'],
                'author'        => $m['author'] ?? 'Erf Talebi',
                'homepage'      => $m['homepage'] ?? 'https://erf.studio',
                'requires'      => $m['requires'] ?? '',
                'tested'        => $m['tested'] ?? '',
                'last_updated'  => $m['last_updated'] ?? '',
                'download_link' => $m['download_url'] ?? '',
                'sections'      => is_array( $m['sections'] ?? null ) ? $m['sections'] : array( 'description' => $m['description'] ?? '' ),
            );
        }, 10, 3 );

        // Drop the manifest cache right after any update runs, so the Plugins
        // screen reflects the new state without waiting 6 hours.
        add_action( 'upgrader_process_complete', function () use ( $cache_key ) {
            delete_transient( $cache_key );
        } );

        // Background auto-update: once a release is published to the channel,
        // every site installs it on its own within a day, no clicks. This is
        // what makes the channel "update once, propagates everywhere". A site
        // can opt out with define('ERF_UPDATER_NO_AUTO', true) in wp-config.
        add_filter( 'auto_update_plugin', function ( $update, $item ) use ( $cfg ) {
            if ( isset( $item->plugin ) && $item->plugin === $cfg['basename'] ) {
                if ( defined( 'ERF_UPDATER_NO_AUTO' ) && ERF_UPDATER_NO_AUTO ) { return $update; }
                return true;
            }
            return $update;
        }, 10, 2 );
    }
}

/* ---- Erfort registers itself ---- */
erf_updater_boot( array(
    'slug'     => 'erf-shield',
    'name'     => 'Erfort',
    'version'  => ERF_SHIELD_VERSION,
    'basename' => plugin_basename( ERF_SHIELD_PATH . 'erf-shield.php' ),
    'manifest' => 'https://updates.erf.studio/erf-shield.json',
) );
