<?php
/**
 * GitHub Releases update checker.
 *
 * @package HalBusinessListings
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use YahnisElsts\PluginUpdateChecker\v5p7\PucFactory;

final class HAL_BL_Updater {

	/**
	 * Matches this plugin's release assets only; must match the ZIP name built by the release workflow.
	 */
	private const ASSET_REGEX = '/^hal-business-listings.*\.zip$/i';

	public static function init(): void {
		if ( ! defined( 'HAL_BL_GITHUB_REPO' ) || '' === HAL_BL_GITHUB_REPO ) {
			return;
		}

		$library = plugin_dir_path( HAL_BL_FILE ) . 'vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php';
		if ( ! is_readable( $library ) ) {
			return;
		}

		// Another plugin may have loaded the same namespace already; reuse its copy.
		if ( ! class_exists( PucFactory::class, false ) ) {
			require_once $library;
		}

		if ( ! class_exists( PucFactory::class ) ) {
			return;
		}

		try {
			PucFactory::buildUpdateChecker(
				HAL_BL_GITHUB_REPO,
				HAL_BL_FILE,
				'hal-business-listings'
			)->getVcsApi()->enableReleaseAssets( self::ASSET_REGEX );
		} catch ( \Throwable $e ) {
			// A broken update system must never take the plugin down.
		}
	}
}
add_action( 'plugins_loaded', array( 'HAL_BL_Updater', 'init' ), 20 );
