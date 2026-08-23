<?php
declare(strict_types=1);
defined( 'ABSPATH' ) || exit;

const HAL_BL_AMELIA_CATALOG_TRANSIENT = 'hal_bl_amelia_catalog';
const HAL_BL_AMELIA_ERROR_TRANSIENT = 'hal_bl_amelia_catalog_error';
const HAL_BL_AMELIA_SYNC_HOOK = 'hal_bl_amelia_catalog_sync';

function hal_bl_amelia_settings_defaults(): array { return array( 'api_key' => '', 'general_service_id' => 0, 'buyer_service_id' => 0, 'seller_service_id' => 0, 'general_category_id' => 0, 'buyer_category_id' => 0, 'seller_category_id' => 0, 'general_provider_id' => 0, 'buyer_provider_id' => 0, 'seller_provider_id' => 0 ); }
function hal_bl_get_amelia_settings(): array { return wp_parse_args( (array) get_option( 'hal_bl_amelia_settings', array() ), hal_bl_amelia_settings_defaults() ); }
function hal_bl_amelia_api_key(): string { $s = hal_bl_get_amelia_settings(); return defined( 'HAL_BL_AMELIA_API_KEY' ) ? trim( (string) HAL_BL_AMELIA_API_KEY ) : trim( (string) $s['api_key'] ); }
function hal_bl_amelia_api_key_mask(): string { return '************'; }
function hal_bl_sanitize_amelia_settings( $input ): array {
	$input = (array) $input;
	$old   = hal_bl_get_amelia_settings();
	$key   = (string) $old['api_key'];
	if ( ! defined( 'HAL_BL_AMELIA_API_KEY' ) ) { if ( ! empty( $input['clear_api_key'] ) ) { $key = ''; } elseif ( ! empty( $input['api_key'] ) && hal_bl_amelia_api_key_mask() !== $input['api_key'] ) { $key = substr( sanitize_text_field( wp_unslash( $input['api_key'] ) ), 0, 512 ); } }

	$settings = array( 'api_key' => $key );
	foreach ( array( 'general', 'buyer', 'seller' ) as $type ) { foreach ( array( 'service', 'category', 'provider' ) as $entity ) { $settings[ $type . '_' . $entity . '_id' ] = absint( $input[ $type . '_' . $entity . '_id' ] ?? 0 ); } }

	if ( ! defined( 'HAL_BL_AMELIA_API_KEY' ) && ! hash_equals( (string) $old['api_key'], (string) $settings['api_key'] ) ) {
		delete_transient( HAL_BL_AMELIA_CATALOG_TRANSIENT );
		delete_transient( HAL_BL_AMELIA_ERROR_TRANSIENT );
	}

	return $settings;
}
function hal_bl_register_amelia_settings(): void { register_setting( 'hal_bl_amelia_settings_group', 'hal_bl_amelia_settings', array( 'type' => 'array', 'sanitize_callback' => 'hal_bl_sanitize_amelia_settings', 'default' => hal_bl_amelia_settings_defaults() ) ); }
add_action( 'admin_init', 'hal_bl_register_amelia_settings' );
function hal_bl_amelia_api_url( string $path, array $query = array() ): string { return add_query_arg( array_merge( $query, array( 'action' => 'wpamelia_api', 'call' => '/api/v1/' . ltrim( $path, '/' ) ) ), admin_url( 'admin-ajax.php' ) ); }
function hal_bl_amelia_health( string $state, string $detail = '' ): void { update_option( 'hal_bl_amelia_health', array( 'checked_at' => time(), 'state' => sanitize_key( $state ), 'detail' => sanitize_key( $detail ) ) ); }
function hal_bl_amelia_request( string $path, array $query = array() ): array {
	$key = hal_bl_amelia_api_key(); if ( '' === $key ) { return array( 'ok' => false, 'error' => 'missing_api_key' ); }
	$r = wp_remote_get( hal_bl_amelia_api_url( $path, $query ), array( 'headers' => array( 'Amelia' => $key, 'Accept' => 'application/json' ), 'timeout' => 15, 'redirection' => 0, 'sslverify' => true ) );
	if ( is_wp_error( $r ) ) { return array( 'ok' => false, 'error' => 'transport_error' ); }
	$code = (int) wp_remote_retrieve_response_code( $r ); if ( 200 !== $code ) { return array( 'ok' => false, 'error' => 'http_' . $code ); }
	$p = json_decode( wp_remote_retrieve_body( $r ), true ); return is_array( $p ) ? array( 'ok' => true, 'data' => $p['data'] ?? $p ) : array( 'ok' => false, 'error' => 'invalid_payload' );
}
function hal_bl_amelia_paged( string $path, string $key ): array {
	$all = array(); for ( $page = 1; $page <= 20; $page++ ) { $r = hal_bl_amelia_request( $path, array( 'page' => $page ) ); if ( ! $r['ok'] ) return $r; $rows = $r['data'][ $key ] ?? $r['data'][ 'serviceList' ] ?? $r['data'][ 'providers' ] ?? array(); if ( ! is_array( $rows ) ) return array( 'ok' => false, 'error' => 'missing_' . $key ); $all = array_merge( $all, $rows ); $total = absint( $r['data']['countTotal'] ?? $r['data']['countFiltered'] ?? 0 ); if ( ! $rows || ( $total && count( $all ) >= $total ) ) return array( 'ok' => true, 'items' => $all ); } return array( 'ok' => false, 'error' => 'page_limit_reached' );
}
function hal_bl_fetch_amelia_catalog(): array {
	@set_time_limit( 60 ); $s = hal_bl_amelia_paged( '/services', 'services' ); $p = hal_bl_amelia_paged( '/users/providers', 'users' ); $c = hal_bl_amelia_request( '/categories' );
	if ( ! $s['ok'] || ! $p['ok'] || ! $c['ok'] || ! is_array( $c['data']['categories'] ?? null ) ) { $e = $s['error'] ?? $p['error'] ?? $c['error'] ?? 'invalid_catalog'; hal_bl_amelia_health( 'error', $e ); set_transient( HAL_BL_AMELIA_ERROR_TRANSIENT, $e, 15 * MINUTE_IN_SECONDS ); return array(); }
	$catalog = array( 'schema' => 1, 'fetched_at' => time(), 'services' => array(), 'categories' => array(), 'providers' => array(), 'service_providers' => array() );
	foreach ( $s['items'] as $v ) { $id = absint( $v['id'] ?? 0 ); if ( $id ) $catalog['services'][ $id ] = sanitize_text_field( (string) ( $v['name'] ?? '' ) ); }
	foreach ( $c['data']['categories'] as $v ) { $id = absint( $v['id'] ?? 0 ); if ( $id ) $catalog['categories'][ $id ] = array( 'name' => sanitize_text_field( (string) ( $v['name'] ?? '' ) ), 'position' => absint( $v['position'] ?? 0 ), 'services' => array_map( 'absint', wp_list_pluck( (array) ( $v['serviceList'] ?? array() ), 'id' ) ) ); }
	foreach ( $p['items'] as $v ) { $id = absint( $v['id'] ?? 0 ); if ( ! $id ) continue; $catalog['providers'][ $id ] = sanitize_text_field( trim( (string) ( $v['firstName'] ?? '' ) . ' ' . (string) ( $v['lastName'] ?? '' ) ) ); foreach ( (array) ( $v['serviceList'] ?? array() ) as $service ) { $sid = absint( is_array( $service ) ? ( $service['id'] ?? 0 ) : $service ); if ( $sid ) $catalog['service_providers'][ $sid ][] = $id; } }
	asort( $catalog['services'], SORT_NATURAL | SORT_FLAG_CASE ); set_transient( HAL_BL_AMELIA_CATALOG_TRANSIENT, $catalog, 12 * HOUR_IN_SECONDS ); delete_transient( HAL_BL_AMELIA_ERROR_TRANSIENT ); hal_bl_amelia_health( empty( $catalog['services'] ) ? 'success_empty' : 'ready' ); return $catalog;
}
function hal_bl_get_amelia_catalog( bool $force = false ): array {
	$c = get_transient( HAL_BL_AMELIA_CATALOG_TRANSIENT );
	if ( ! $force && get_transient( HAL_BL_AMELIA_ERROR_TRANSIENT ) ) {
		return is_array( $c ) ? $c : array();
	}
	return ! $force && is_array( $c ) ? $c : hal_bl_fetch_amelia_catalog();
}
function hal_bl_get_amelia_services( bool $force = false ): array { $c = hal_bl_get_amelia_catalog( $force ); return (array) ( $c['services'] ?? array() ); }
function hal_bl_get_cached_amelia_catalog(): array { $catalog = get_transient( HAL_BL_AMELIA_CATALOG_TRANSIENT ); return is_array( $catalog ) ? $catalog : array(); }
function hal_bl_amelia_sync(): void { hal_bl_get_amelia_catalog(); }
add_action( HAL_BL_AMELIA_SYNC_HOOK, 'hal_bl_amelia_sync' );
add_action( 'init', static function (): void { if ( ! wp_next_scheduled( HAL_BL_AMELIA_SYNC_HOOK ) ) wp_schedule_event( time() + HOUR_IN_SECONDS, 'twicedaily', HAL_BL_AMELIA_SYNC_HOOK ); } );
function hal_bl_amelia_invalidate_catalog(): void { delete_transient( HAL_BL_AMELIA_CATALOG_TRANSIENT ); delete_transient( HAL_BL_AMELIA_ERROR_TRANSIENT ); wp_schedule_single_event( time() + MINUTE_IN_SECONDS, HAL_BL_AMELIA_SYNC_HOOK ); }
foreach ( array( 'amelia_after_service_added', 'amelia_after_service_updated', 'amelia_after_service_deleted', 'amelia_after_category_added', 'amelia_after_category_updated', 'amelia_after_category_deleted', 'amelia_after_provider_added', 'amelia_after_provider_updated', 'amelia_after_provider_deleted' ) as $hook ) { add_action( $hook, 'hal_bl_amelia_invalidate_catalog' ); }
function hal_bl_refresh_amelia_services(): void { if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'You are not allowed to refresh this integration.', 'hal-business-listings' ) ); check_admin_referer( 'hal_bl_refresh_amelia_services' ); $c = hal_bl_get_amelia_catalog( true ); wp_safe_redirect( add_query_arg( array( 'post_type' => 'business_listing', 'page' => 'hal-bl-booking-integration', 'hal_bl_api_refresh' => $c ? 'success' : 'failed' ), admin_url( 'edit.php' ) ) ); exit; }
add_action( 'admin_post_hal_bl_refresh_amelia_services', 'hal_bl_refresh_amelia_services' );
function hal_bl_add_amelia_settings_page(): void { add_submenu_page( 'edit.php?post_type=business_listing', __( 'Integrations', 'hal-business-listings' ), __( 'Integrations', 'hal-business-listings' ), 'manage_options', 'hal-bl-booking-integration', 'hal_bl_render_amelia_settings_page' ); }
add_action( 'admin_menu', 'hal_bl_add_amelia_settings_page' );
function hal_bl_render_amelia_settings_page(): void { if ( ! current_user_can( 'manage_options' ) ) return; $s = hal_bl_get_amelia_settings(); $services = hal_bl_get_amelia_services(); ?>
<div class="wrap"><h1><?php esc_html_e( 'Business Listings Integrations', 'hal-business-listings' ); ?></h1><p><?php esc_html_e( 'The API key remains on the server. Services, categories, and employees are synchronized automatically; booking uses Amelia’s own shortcode or builder widget.', 'hal-business-listings' ); ?></p>
<?php if ( isset( $_GET['hal_bl_api_refresh'] ) ) : ?><div class="notice <?php echo 'success' === sanitize_key( wp_unslash( $_GET['hal_bl_api_refresh'] ) ) ? 'notice-success' : 'notice-error'; ?>"><p><?php echo 'success' === sanitize_key( wp_unslash( $_GET['hal_bl_api_refresh'] ) ) ? esc_html__( 'Amelia catalog refreshed.', 'hal-business-listings' ) : esc_html__( 'Amelia catalog refresh failed; the last valid catalog remains in use.', 'hal-business-listings' ); ?></p></div><?php endif; ?>
<form action="options.php" method="post"><?php settings_fields( 'hal_bl_amelia_settings_group' ); ?><table class="form-table"><tr><th><label for="hal-bl-api-key"><?php esc_html_e( 'Amelia API key', 'hal-business-listings' ); ?></label></th><td><?php if ( defined( 'HAL_BL_AMELIA_API_KEY' ) ) : ?><strong><?php esc_html_e( 'Provided by server configuration.', 'hal-business-listings' ); ?></strong><?php else : ?><input id="hal-bl-api-key" name="hal_bl_amelia_settings[api_key]" type="password" value="<?php echo esc_attr( $s['api_key'] ? hal_bl_amelia_api_key_mask() : '' ); ?>" /><label><input name="hal_bl_amelia_settings[clear_api_key]" type="checkbox" value="1" /> <?php esc_html_e( 'Remove saved key', 'hal-business-listings' ); ?></label><?php endif; ?></td></tr>
<?php $catalog = hal_bl_get_amelia_catalog(); foreach ( array( 'general' => __( 'Initial consultation', 'hal-business-listings' ), 'buyer' => __( 'Buyer introduction', 'hal-business-listings' ), 'seller' => __( 'Seller intake', 'hal-business-listings' ) ) as $type => $label ) : foreach ( array( 'service' => $services, 'category' => wp_list_pluck( (array) ( $catalog['categories'] ?? array() ), 'name' ), 'provider' => (array) ( $catalog['providers'] ?? array() ) ) as $entity => $choices ) : $key = $type . '_' . $entity . '_id'; ?><tr><th><label for="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $label . ' — ' . ucfirst( $entity ) ); ?></label></th><td><select id="<?php echo esc_attr( $key ); ?>" name="hal_bl_amelia_settings[<?php echo esc_attr( $key ); ?>]"><option value="0"><?php esc_html_e( 'No restriction', 'hal-business-listings' ); ?></option><?php foreach ( $choices as $id => $name ) : ?><option value="<?php echo esc_attr( $id ); ?>" <?php selected( (int) $s[ $key ], $id ); ?>><?php echo esc_html( $name ); ?></option><?php endforeach; ?></select></td></tr><?php endforeach; endforeach; ?></table><?php submit_button(); ?></form>
<form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post"><input type="hidden" name="action" value="hal_bl_refresh_amelia_services" /><?php wp_nonce_field( 'hal_bl_refresh_amelia_services' ); submit_button( __( 'Refresh Amelia catalog', 'hal-business-listings' ), 'secondary' ); ?></form></div><?php }
function hal_bl_amelia_mapping_prefix( string $type ): string { return array( 'general' => 'general', 'buyer_intro' => 'buyer', 'seller_intake' => 'seller' )[ $type ] ?? ''; }
function hal_bl_amelia_service_id( string $type ): int { $s = hal_bl_get_amelia_settings(); return absint( $s[ hal_bl_amelia_mapping_prefix( $type ) . '_service_id' ] ?? 0 ); }
function hal_bl_amelia_booking_markup( string $type ): string { $prefix = hal_bl_amelia_mapping_prefix( $type ); $s = hal_bl_get_amelia_settings(); $c = hal_bl_get_cached_amelia_catalog(); $args = array(); foreach ( array( 'service', 'category', 'provider' => 'employee' ) as $setting => $shortcode ) { if ( is_int( $setting ) ) { $setting = $shortcode; } $id = absint( $s[ $prefix . '_' . $setting . '_id' ] ?? 0 ); if ( $id ) $args[] = ( 'provider' === $setting ? 'employee' : $setting ) . '="' . $id . '"'; } return shortcode_exists( 'ameliastepbooking' ) && ( ! empty( $args ) || ! empty( $c ) ) ? do_shortcode( '[ameliastepbooking ' . implode( ' ', $args ) . ']' ) : ''; }
function hal_bl_get_contact_cta_html( string $label ): string { return '<a href="' . esc_url( home_url( '/contact/' ) ) . '" class="hal-bl-cta hal-bl-cta-contact">' . esc_html( $label ) . '</a>'; }
function hal_bl_get_consultation_cta_html(): string { return hal_bl_amelia_booking_markup( 'general' ) ?: hal_bl_get_contact_cta_html( __( 'Contact Us for a Consultation', 'hal-business-listings' ) ); }
function hal_bl_get_reserve_cta_html( int $post_id ): string { $status = function_exists( 'get_field' ) ? get_field( 'listing_status', $post_id ) : get_post_meta( $post_id, 'listing_status', true ); if ( 'sold' === $status ) return '<span class="hal-bl-badge hal-bl-badge-sold">' . esc_html__( 'Sold', 'hal-business-listings' ) . '</span>'; if ( 'reserved' === $status ) return '<p class="hal-bl-cta-note" role="status">' . esc_html__( 'Currently reserved. Contact us for similar opportunities.', 'hal-business-listings' ) . '</p>'; return hal_bl_amelia_booking_markup( 'buyer_intro' ) ?: hal_bl_get_contact_cta_html( __( 'Request Confidential Details', 'hal-business-listings' ) ); }
function hal_bl_seller_intake_cta_shortcode(): string { return hal_bl_amelia_booking_markup( 'seller_intake' ) ?: hal_bl_get_contact_cta_html( __( 'Discuss Selling Your Company', 'hal-business-listings' ) ); }
add_shortcode( 'hal_bl_seller_cta', 'hal_bl_seller_intake_cta_shortcode' ); add_shortcode( 'hal_bl_consultation_cta', 'hal_bl_get_consultation_cta_html' ); add_shortcode( 'hal_bl_reserve_cta', static function (): string { return get_the_ID() ? hal_bl_get_reserve_cta_html( (int) get_the_ID() ) : ''; } );
