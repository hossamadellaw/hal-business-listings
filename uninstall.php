<?php
/**
 * Uninstall handler.
 *
 * Runs only when the plugin is deleted from the Plugins screen
 * (never on simple deactivation). WordPress guarantees WP_UNINSTALL_PLUGIN
 * is defined before including this file — used as a safety check to
 * prevent direct access.
 *
 * By design, this intentionally does NOT delete:
 *  - business_listing posts (real client/company data)
 *  - listing_country terms
 *  - any post meta (company_gallery, seller contact fields, etc.)
 *  - the ACF field group (it lives in this plugin's code, not the DB)
 *
 * Deleting a plugin should never silently destroy real business data.
 * If a full data wipe is ever needed, do it deliberately and manually.
 * Only the small internal housekeeping option below is removed.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Static list mirroring hal_bl_listing_capabilities() plus the default seller
 * capability. Kept standalone on purpose: this file runs isolated, and
 * requiring plugin files here would fatal on the undefined HAL_BL_FILE
 * constant. A site filtering hal_bl_seller_field_capability to a custom name
 * leaves that custom capability behind — accepted constraint of isolation.
 */
function hal_bl_uninstall_capabilities(): array {
	return array(
		'edit_business_listing',
		'read_business_listing',
		'delete_business_listing',
		'edit_business_listings',
		'edit_others_business_listings',
		'publish_business_listings',
		'read_private_business_listings',
		'delete_business_listings',
		'delete_private_business_listings',
		'delete_published_business_listings',
		'delete_others_business_listings',
		'edit_private_business_listings',
		'edit_published_business_listings',
		'manage_hal_bl_sensitive_data',
	);
}

function hal_bl_remove_capabilities_for_site(): void {
	$role = get_role( 'administrator' );
	if ( ! $role ) {
		return;
	}

	foreach ( hal_bl_uninstall_capabilities() as $cap ) {
		$role->remove_cap( $cap );
	}
}

function hal_bl_uninstall_site(): void {
	delete_option( 'hal_bl_countries_seeded' );
	delete_option( 'hal_bl_schema_version' );
	delete_option( 'hal_bl_amelia_settings' );
	delete_option( 'hal_bl_amelia_health' );
	delete_option( 'hal_bl_amelia_event_log' );
	delete_option( 'hal_bl_context_page_id' );
	delete_option( 'hal_bl_country_seed_lock' );
	delete_option( 'hal_bl_seller_migration_lock' );
	delete_option( 'hal_bl_seller_migration_cursor' );
	delete_option( 'hal_bl_visual_policy_review_lock' );
	delete_option( 'hal_bl_visual_policy_review_cursor' );
	delete_option( 'hal_bl_visual_policy_pending' );
	delete_transient( 'hal_bl_amelia_catalog' );
	delete_transient( 'hal_bl_amelia_catalog_error' );
	wp_clear_scheduled_hook( 'hal_bl_amelia_catalog_sync' );

	hal_bl_remove_capabilities_for_site();
}

if ( is_multisite() ) {
	$site_ids = get_sites( array( 'fields' => 'ids' ) );
	foreach ( $site_ids as $site_id ) {
		switch_to_blog( (int) $site_id );
		hal_bl_uninstall_site();
		restore_current_blog();
	}
} else {
	hal_bl_uninstall_site();
}
