<?php
declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HAL_BL_Display {
	/** Returns only the public listing fields; confidential seller meta is never read here. */
	public static function public_fields( int $post_id ): array {
		if ( 'business_listing' !== get_post_type( $post_id ) ) {
			return array();
		}

		$value = static function ( string $field_name ) use ( $post_id ) {
			return function_exists( 'get_field' ) ? get_field( $field_name, $post_id ) : get_post_meta( $post_id, $field_name, true );
		};
		$terms = get_the_terms( $post_id, 'listing_country' );

		return array(
			'reference'   => $value( 'company_reference' ),
			'country'     => is_array( $terms ) ? wp_list_pluck( $terms, 'name' ) : array(),
			'city'        => $value( 'company_city' ),
			'industry'    => $value( 'company_industry' ),
			'legal_form'  => $value( 'legal_form' ),
			'year'        => $value( 'year_established' ),
			'employees'   => $value( 'employee_count' ),
			'price_mode'  => $value( 'price_display_mode' ),
			'price_range' => $value( 'price_range' ),
			'gallery'     => hal_bl_get_gallery_html( $post_id ),
			'status'      => $value( 'listing_status' ),
		);
	}

	public static function can_display_public_visual( int $post_id ): bool {
		return '1' === get_post_meta( $post_id, 'public_visual_approved', true );
	}

	public static function render_visual( int $post_id, string $size = 'large' ): string {
		if ( self::can_display_public_visual( $post_id ) && has_post_thumbnail( $post_id ) ) {
			return get_the_post_thumbnail( $post_id, $size, array( 'loading' => 'lazy' ) );
		}

		return '<div class="hal-bl-visual-placeholder" role="img" aria-label="' . esc_attr__( 'Listing image unavailable', 'hal-business-listings' ) . '"></div>';
	}

	public static function render_status( $status ): string {
		$labels = array(
			'available'   => __( 'Available', 'hal-business-listings' ),
			'negotiation' => __( 'Under negotiation', 'hal-business-listings' ),
			'reserved'    => __( 'Reserved', 'hal-business-listings' ),
			'sold'        => __( 'Sold', 'hal-business-listings' ),
		);
		$status = is_string( $status ) ? $status : '';
		if ( ! isset( $labels[ $status ] ) ) {
			return '';
		}

		return '<p class="hal-bl-status hal-bl-status-' . esc_attr( $status ) . '">' . esc_html( $labels[ $status ] ) . '</p>';
	}

	public static function render_listing_details( array $fields ): string {
		$labels = array(
			'reference'   => __( 'Reference', 'hal-business-listings' ),
			'country'     => __( 'Country', 'hal-business-listings' ),
			'city'        => __( 'City', 'hal-business-listings' ),
			'industry'    => __( 'Industry', 'hal-business-listings' ),
			'legal_form'  => __( 'Legal form', 'hal-business-listings' ),
			'year'        => __( 'Year established', 'hal-business-listings' ),
			'employees'   => __( 'Employees', 'hal-business-listings' ),
			'price_mode'  => __( 'Price', 'hal-business-listings' ),
			'price_range' => __( 'Price range', 'hal-business-listings' ),
		);
		$items = '';
		foreach ( $labels as $key => $label ) {
			$value = $fields[ $key ] ?? '';
			if ( is_array( $value ) ) {
				$value = implode( ', ', array_map( 'strval', $value ) );
			}
			if ( '' === (string) $value ) {
				continue;
			}
			$items .= '<div><dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( (string) $value ) . '</dd></div>';
		}

		return '' === $items ? '' : '<dl class="hal-bl-listing-details">' . $items . '</dl>';
	}

	public static function render_listing_cta( int $post_id ): string {
		return function_exists( 'hal_bl_get_reserve_cta_html' ) ? hal_bl_get_reserve_cta_html( $post_id ) : '';
	}

	public static function template_include( string $template ): string {
		$type = is_singular( 'business_listing' ) ? 'single' :
			( is_post_type_archive( 'business_listing' ) ? 'archive' : '' );

		// Theme / Theme Builder is the default path; the plugin fallback is an explicit opt-in.
		if ( '' === $type || ! apply_filters( 'hal_bl_use_plugin_templates', false, $type, $template ) ) {
			return $template;
		}

		$candidate = plugin_dir_path( HAL_BL_FILE ) . "templates/{$type}-business_listing.php";
		return is_readable( $candidate ) ? $candidate : $template;
	}
}

/** Backward-compatible public-data helper for existing theme integrations. */
function hal_get_public_listing_fields( int $post_id ): array {
	return HAL_BL_Display::public_fields( $post_id );
}

add_filter( 'template_include', array( 'HAL_BL_Display', 'template_include' ), 99 );
