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

function hal_bl_remove_capabilities_for_site(): void {
	$role = get_role( 'administrator' );
	if ( ! $role ) {
		return;
	}

	// The ledger is the only ownership source: an entry classified
	// 'granted' was absent from the role before this plugin's first grant
	// of it, so HAL introduced it. Entries classified 'pre_existing'
	// pre-dated HAL and belong to whoever placed them. Without a ledger
	// nothing is removable — origin unproven.
	$ledger = get_option( 'hal_bl_capabilities_ledger', false );
	if ( ! is_array( $ledger ) ) {
		return;
	}

	foreach ( $ledger as $cap => $origin ) {
		if ( 'granted' === $origin ) {
			$role->remove_cap( (string) $cap );
		}
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
	delete_option( 'hal_bl_capabilities_ledger' );
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
