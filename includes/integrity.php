<?php
/**
 * Core file integrity check.
 *
 * NOT the signature/malware scanner the core file rules out: this is
 * deterministic. WordPress.org publishes an md5 for every file it ships in a
 * given version. We fetch that official manifest (the one legitimate outbound
 * call, to the canonical source, carrying only the version number), then hash
 * the installed core files and report any that differ or that exist but should
 * not. A changed core file on shared hosting is the classic compromise tell.
 *
 * Scheduled daily, plus an on-demand button. Report only: it never edits or
 * deletes anything. Findings surface in the Erfort page and, if there are any,
 * one email goes to the admin.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Shared alert helper (defined by whichever pro module loads first). */
if ( ! function_exists( 'erf_shield_alert' ) ) {
    function erf_shield_alert( $subject, $body ) {
        $to = get_option( 'admin_email' );
        if ( ! $to ) { return; }
        // Throttle: one alert of a given subject per 6 hours, so a daily scan
        // that keeps finding the same thing does not spam the inbox.
        $k = 'erf_shield_alert_' . md5( $subject );
        if ( get_transient( $k ) ) { return; }
        set_transient( $k, 1, 6 * HOUR_IN_SECONDS );
        wp_mail( $to, '[Erfort] ' . $subject . ' - ' . wp_parse_url( home_url(), PHP_URL_HOST ), $body );
    }
}

function erf_shield_integrity_on() {
    $o = get_option( 'erf_shield_integrity', array( 'enabled' => 1 ) );
    return ! empty( $o['enabled'] );
}

/**
 * Run the check. Returns array('checked'=>int,'modified'=>[],'missing'=>[],'unknown'=>[],'error'=>'').
 */
function erf_shield_integrity_run() {
    global $wp_version, $wp_local_package;
    require_once ABSPATH . 'wp-admin/includes/update.php';

    $locale    = $wp_local_package ?? 'en_US';
    $checksums = get_core_checksums( $wp_version, $locale );
    if ( ! is_array( $checksums ) || empty( $checksums ) ) {
        // Retry with en_US, then give up gracefully.
        $checksums = get_core_checksums( $wp_version, 'en_US' );
    }
    if ( ! is_array( $checksums ) || empty( $checksums ) ) {
        return array( 'checked' => 0, 'modified' => array(), 'missing' => array(), 'unknown' => array(), 'error' => 'Could not fetch official checksums from WordPress.org.', 'time' => time() );
    }

    $modified = array();
    $missing  = array();
    $checked  = 0;
    foreach ( $checksums as $file => $md5 ) {
        // wp-content is the site's own; only core dirs are covered by checksums.
        if ( 0 === strpos( $file, 'wp-content/' ) ) { continue; }
        $path = ABSPATH . $file;
        if ( ! file_exists( $path ) ) {
            // Some optional files legitimately absent; only flag core PHP.
            if ( preg_match( '#^wp-(admin|includes)/.+\.php$#', $file ) ) { $missing[] = $file; }
            continue;
        }
        $checked++;
        if ( md5_file( $path ) !== $md5 ) { $modified[] = $file; }
    }

    // Unexpected extra PHP files sitting in the core directories.
    $unknown = array();
    foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
        $base = ABSPATH . $dir;
        if ( ! is_dir( $base ) ) { continue; }
        $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ) );
        foreach ( $it as $f ) {
            if ( 'php' !== strtolower( $f->getExtension() ) ) { continue; }
            $rel = str_replace( ABSPATH, '', $f->getPathname() );
            $rel = str_replace( '\\', '/', $rel );
            if ( ! isset( $checksums[ $rel ] ) ) { $unknown[] = $rel; }
            if ( count( $unknown ) > 100 ) { break 2; } // sanity cap
        }
    }

    $result = array(
        'checked'  => $checked,
        'modified' => $modified,
        'missing'  => $missing,
        'unknown'  => $unknown,
        'error'    => '',
        'time'     => time(),
        'version'  => $wp_version,
    );
    update_option( 'erf_shield_integrity_result', $result, false );

    $bad = count( $modified ) + count( $missing ) + count( $unknown );
    if ( $bad > 0 ) {
        if ( function_exists( 'erf_shield_log' ) ) { erf_shield_log( 'integrity', $bad . ' core file issue(s)' ); }
        $lines = array( 'Core file integrity check found issues on ' . home_url() . ':', '' );
        if ( $modified ) { $lines[] = 'Modified: ' . implode( ', ', array_slice( $modified, 0, 20 ) ); }
        if ( $missing )  { $lines[] = 'Missing: ' . implode( ', ', array_slice( $missing, 0, 20 ) ); }
        if ( $unknown )  { $lines[] = 'Unexpected: ' . implode( ', ', array_slice( $unknown, 0, 20 ) ); }
        $lines[] = '';
        $lines[] = 'Review under Erfort in wp-admin. Erfort does not change files; you decide.';
        erf_shield_alert( 'core files changed', implode( "\n", $lines ) );
    }
    return $result;
}

/* ---------------------------------------------------- plugin integrity
 * A tampered plugin is a more common compromise than tampered core. The plugin
 * directory publishes per-file md5s for every hosted version, so we can check
 * installed .org plugins the same deterministic way. Premium and custom plugins
 * (no published checksums, e.g. Erfort itself) are skipped, never flagged.
 * Checksums are immutable per version, so we cache them for 14 days to keep the
 * daily scan and the on-demand button cheap. Report only. */

function erf_shield_integrity_plugin_checksums( $slug, $version ) {
    $key    = 'erf_shield_pchk_' . md5( $slug . '@' . $version );
    $cached = get_transient( $key );
    if ( false !== $cached ) { return is_array( $cached ) ? $cached : null; } // 'no' => not on .org
    $url  = "https://downloads.wordpress.org/plugin-checksums/{$slug}/{$version}.json";
    $resp = wp_remote_get( $url, array( 'timeout' => 8 ) );
    if ( is_wp_error( $resp ) || 200 !== (int) wp_remote_retrieve_response_code( $resp ) ) {
        set_transient( $key, 'no', 14 * DAY_IN_SECONDS );
        return null;
    }
    $json  = json_decode( wp_remote_retrieve_body( $resp ), true );
    $files = ( ! empty( $json['files'] ) && is_array( $json['files'] ) ) ? $json['files'] : null;
    set_transient( $key, $files ? $files : 'no', 14 * DAY_IN_SECONDS );
    return $files;
}

/** Returns array('checked'=>int,'skipped'=>int,'issues'=>[ ['plugin','version','files'] ],'time'). */
function erf_shield_integrity_plugins_run() {
    if ( ! function_exists( 'get_plugins' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
    $checked = 0; $skipped = 0; $issues = array();
    foreach ( get_plugins() as $file => $data ) {
        $slug    = ( false !== strpos( $file, '/' ) ) ? dirname( $file ) : basename( $file, '.php' );
        $version = $data['Version'] ?? '';
        if ( '' === $version ) { $skipped++; continue; }
        $sums = erf_shield_integrity_plugin_checksums( $slug, $version );
        if ( null === $sums ) { $skipped++; continue; } // premium/custom/not hosted
        $checked++;
        $dir = WP_PLUGIN_DIR . '/' . $slug;
        $bad = array();
        foreach ( $sums as $rel => $hashes ) {
            $md5 = is_array( $hashes ) ? ( $hashes['md5'] ?? '' ) : '';
            if ( '' === $md5 ) { continue; }
            $path = $dir . '/' . $rel;
            if ( ! file_exists( $path ) ) { continue; } // absent optional file; don't over-flag
            if ( md5_file( $path ) !== $md5 ) { $bad[] = $rel; }
            if ( count( $bad ) > 20 ) { break; }
        }
        if ( $bad ) { $issues[] = array( 'plugin' => $slug, 'version' => $version, 'files' => $bad ); }
    }
    $result = array( 'checked' => $checked, 'skipped' => $skipped, 'issues' => $issues, 'time' => time() );
    update_option( 'erf_shield_integrity_plugins_result', $result, false );

    if ( $issues ) {
        if ( function_exists( 'erf_shield_log' ) ) { erf_shield_log( 'integrity', count( $issues ) . ' plugin(s) with changed files' ); }
        $lines = array( 'Plugin integrity check found changed files on ' . home_url() . ':', '' );
        foreach ( $issues as $i ) { $lines[] = $i['plugin'] . ' v' . $i['version'] . ': ' . implode( ', ', array_slice( $i['files'], 0, 10 ) ); }
        $lines[] = '';
        $lines[] = 'A changed plugin file can be a compromise. Review under Erfort. Erfort does not change files; you decide.';
        erf_shield_alert( 'plugin files changed', implode( "\n", $lines ) );
    }
    return $result;
}

/* schedule daily (core + plugins share the one cron and the one button) */
add_action( 'erf_shield_integrity_cron', function () { if ( erf_shield_integrity_on() ) { erf_shield_integrity_run(); erf_shield_integrity_plugins_run(); } } );
add_action( 'init', function () {
    if ( erf_shield_integrity_on() && ! wp_next_scheduled( 'erf_shield_integrity_cron' ) ) {
        wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'erf_shield_integrity_cron' );
    }
} );

/* admin: toggle + on-demand run + result table */
add_action( 'admin_init', function () {
    if ( ! is_admin() ) { return; }
    if ( ! empty( $_POST['erf_shield_integrity_save'] ) && current_user_can( 'manage_options' ) && check_admin_referer( 'erf_shield_integrity' ) ) {
        update_option( 'erf_shield_integrity', array( 'enabled' => empty( $_POST['erf_shield_integrity_enabled'] ) ? 0 : 1 ) );
    }
    if ( ! empty( $_POST['erf_shield_integrity_run'] ) && current_user_can( 'manage_options' ) && check_admin_referer( 'erf_shield_integrity' ) ) {
        erf_shield_integrity_run();
        erf_shield_integrity_plugins_run();
    }
} );

add_action( 'erf_shield_page_sections', function () {
    $on  = erf_shield_integrity_on();
    $res = get_option( 'erf_shield_integrity_result', array() );
    ?>
    <div class="box">
      <h2>core file integrity</h2>
      <form method="post">
        <?php wp_nonce_field( 'erf_shield_integrity' ); ?>
        <label><input type="checkbox" name="erf_shield_integrity_enabled" <?php checked( $on ); ?>> compare WordPress core files, and installed WordPress.org plugins, against the official checksums daily, and flag any that were changed, removed, or added. premium and custom plugins are skipped. report only, nothing is ever edited.</label>
        <p style="margin-top:10px">
          <button class="button button-primary" name="erf_shield_integrity_save" value="1">save</button>
          <button class="button" name="erf_shield_integrity_run" value="1">scan now</button>
        </p>
      </form>
      <?php if ( ! empty( $res ) ) : ?>
        <table style="margin-top:12px">
          <?php if ( $res['error'] ) : ?>
            <tr><td class="warn"><?php echo esc_html( $res['error'] ); ?></td></tr>
          <?php else :
            $bad = count( $res['modified'] ) + count( $res['missing'] ) + count( $res['unknown'] ); ?>
            <tr><td style="width:170px">last scan</td><td><?php echo esc_html( human_time_diff( (int) $res['time'] ) ); ?> ago, <?php echo (int) $res['checked']; ?> files checked (v<?php echo esc_html( $res['version'] ?? '' ); ?>)</td></tr>
            <tr><td>result</td><td class="<?php echo $bad ? 'warn' : 'ok'; ?>"><?php echo $bad ? esc_html( $bad . ' issue(s) found' ) : 'all core files match'; ?></td></tr>
            <?php foreach ( array( 'modified' => 'modified', 'missing' => 'missing', 'unknown' => 'unexpected' ) as $k => $lbl ) : ?>
              <?php if ( ! empty( $res[ $k ] ) ) : ?>
                <tr><td><?php echo esc_html( $lbl ); ?></td><td class="warn"><?php echo esc_html( implode( ', ', array_slice( $res[ $k ], 0, 30 ) ) ); ?><?php echo count( $res[ $k ] ) > 30 ? ' …' : ''; ?></td></tr>
              <?php endif; ?>
            <?php endforeach; ?>
          <?php endif; ?>
        </table>
      <?php endif; ?>

      <?php $pres = get_option( 'erf_shield_integrity_plugins_result', array() ); if ( ! empty( $pres ) ) : ?>
        <table style="margin-top:12px">
          <tr><td style="width:170px">plugins</td>
              <td>last scan <?php echo esc_html( human_time_diff( (int) $pres['time'] ) ); ?> ago, <?php echo (int) $pres['checked']; ?> checked against WordPress.org, <?php echo (int) $pres['skipped']; ?> skipped (premium or custom)</td></tr>
          <tr><td>result</td>
              <td class="<?php echo empty( $pres['issues'] ) ? 'ok' : 'warn'; ?>"><?php echo empty( $pres['issues'] ) ? 'all checked plugins match' : esc_html( count( $pres['issues'] ) . ' plugin(s) with changed files' ); ?></td></tr>
          <?php foreach ( (array) $pres['issues'] as $i ) : ?>
            <tr><td><?php echo esc_html( $i['plugin'] . ' v' . $i['version'] ); ?></td>
                <td class="warn"><?php echo esc_html( implode( ', ', array_slice( (array) $i['files'], 0, 20 ) ) ); ?></td></tr>
          <?php endforeach; ?>
        </table>
      <?php endif; ?>
    </div>
    <?php
} );
