<?php
/**
 * Plugin Name:       Hossam Adel Law Firm — Business Listings
 * Plugin URI:        https://hossamadellaw.com
 * Description:       Business listings for the Mergers & Acquisitions section.
 * Version:           1.3.2
 * Requires at least: 6.5
 * Requires PHP:      8.3
 * Requires Plugins:  advanced-custom-fields
 * Author:            Hossam Adel Law Firm
 * Text Domain:       hal-business-listings
 * Domain Path:       /languages
 * License:           GPL-2.0-or-later
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'HAL_BL_FILE', __FILE__ );
define( 'HAL_BL_VERSION', '1.3.2' );
define( 'HAL_BL_SCHEMA_VERSION', '1.3.1' );

// GitHub Releases update source — overridable from wp-config.php.
if ( ! defined( 'HAL_BL_GITHUB_REPO' ) ) {
	define( 'HAL_BL_GITHUB_REPO', 'https://github.com/hossamadellaw/hal-business-listings' );
}

require_once __DIR__ . '/includes/class-hal-bl-listings.php';
require_once __DIR__ . '/includes/class-hal-bl-display.php';
require_once __DIR__ . '/includes/class-hal-bl-elementor.php';
require_once __DIR__ . '/includes/class-hal-bl-updater.php';
require_once __DIR__ . '/additions-cta-amelia.php';

function hal_bl_load_textdomain(): void {
	load_plugin_textdomain( 'hal-business-listings', false, dirname( plugin_basename( HAL_BL_FILE ) ) . '/languages' );
}
add_action( 'init', 'hal_bl_load_textdomain' );

function hal_bl_register_frontend_assets(): void {
	$path = plugin_dir_path( HAL_BL_FILE ) . 'assets/css/hal-bl-frontend.css';
	wp_register_style( 'hal-business-listings-frontend', plugin_dir_url( HAL_BL_FILE ) . 'assets/css/hal-bl-frontend.css', array(), is_readable( $path ) ? (string) filemtime( $path ) : HAL_BL_VERSION );
	$blocks_path = plugin_dir_path( HAL_BL_FILE ) . 'assets/css/blocks.css';
	wp_register_style( 'hal-business-listings-blocks', plugin_dir_url( HAL_BL_FILE ) . 'assets/css/blocks.css', array( 'hal-business-listings-frontend' ), is_readable( $blocks_path ) ? (string) filemtime( $blocks_path ) : HAL_BL_VERSION );
}
add_action( 'wp_enqueue_scripts', 'hal_bl_register_frontend_assets' );

function hal_bl_enqueue_frontend_assets(): void {
	if ( is_singular( 'business_listing' ) || is_post_type_archive( 'business_listing' ) || is_tax( 'listing_country' ) ) {
		wp_enqueue_style( 'hal-business-listings-frontend' );
		wp_enqueue_style( 'hal-business-listings-blocks' );
	}
}
add_action( 'wp_enqueue_scripts', 'hal_bl_enqueue_frontend_assets' );

register_activation_hook( HAL_BL_FILE, 'hal_bl_on_activate' );
register_deactivation_hook( HAL_BL_FILE, 'hal_bl_on_deactivate' );
