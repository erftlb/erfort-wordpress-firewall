<?php
/**
 * Erf Admin: shared chrome for in-house plugin admin screens (one topbar
 * component, one credit line) so Colophon, Erfort, and future in-house plugins
 * read as one product line instead of each inventing its own header.
 *
 * An identical copy of this file lives in each plugin (the same pattern as
 * updater.php): every install stays "copy the folder", so every definition and
 * the stylesheet enqueue are guarded against loading twice when more than one
 * Erf plugin is active at once, as they are on erf.studio.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

if ( ! function_exists( 'erf_admin_enqueue' ) ) {
    /** Register + enqueue the shared stylesheet, once, from whichever plugin asks first. */
    function erf_admin_enqueue( $assets_url, $version ) {
        if ( wp_style_is( 'erf-admin-ui', 'registered' ) ) {
            wp_enqueue_style( 'erf-admin-ui' );
            return;
        }
        wp_register_style( 'erf-admin-ui', trailingslashit( $assets_url ) . 'erf-admin.css', array(), $version );
        wp_enqueue_style( 'erf-admin-ui' );
    }
}

if ( ! function_exists( 'erf_admin_topbar' ) ) {
    /**
     * @param string $mark    the product mark, e.g. "Colophon" or "SHIELD".
     * @param string $version plugin version shown in the pill.
     * @param string $who     small right-aligned top line, defaults to the studio credit.
     * @param string $what    small right-aligned bottom line, e.g. "lightweight SEO".
     */
    function erf_admin_topbar( $mark, $version, $who = '', $what = '' ) {
        if ( '' === $who ) { $who = __( 'developed by Erf Talebi', 'erf-seo' ); }
        ?>
        <div class="erf-admin-topbar">
            <span class="mark"><?php echo esc_html( $mark ); ?></span>
            <span class="ver">v<?php echo esc_html( $version ); ?></span>
            <span class="tag">
                <span class="who"><?php echo esc_html( $who ); ?></span>
                <?php if ( '' !== $what ) : ?><span class="what"><?php echo esc_html( $what ); ?></span><?php endif; ?>
            </span>
        </div>
        <?php
    }
}

if ( ! function_exists( 'erf_admin_credit' ) ) {
    function erf_admin_credit( $text ) {
        echo '<p class="erf-admin-credit">' . esc_html( $text ) . '</p>';
    }
}
