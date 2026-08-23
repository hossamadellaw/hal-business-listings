<?php
/**
 * Elementor listing visual widget.
 *
 * @package HalBusinessListings
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class HAL_BL_Elementor_Listing_Visual_Widget extends \Elementor\Widget_Base {
	public function get_name(): string {
		return 'hal-bl-listing-visual';
	}

	public function get_title(): string {
		return esc_html__( 'HAL Listing Visual', 'hal-business-listings' );
	}

	public function get_icon(): string {
		return 'eicon-image-box';
	}

	public function get_categories(): array {
		return array( 'general' );
	}

	public function get_keywords(): array {
		return array( 'business', 'listing', 'image', 'visual', 'hal' );
	}

	public function get_style_depends(): array {
		return array( 'hal-business-listings-frontend' );
	}

	protected function register_controls(): void {}

	protected function render(): void {
		$post_id = get_the_ID();
		if ( ! $post_id || 'business_listing' !== get_post_type( $post_id ) ) {
			return;
		}

		$industry = $this->get_industry_code( (int) $post_id );
		$this->add_render_attribute(
			'visual',
			array(
				'class' => array(
					'hal-bl-listing-visual',
					'hal-bl-listing-visual--' . $industry,
				),
			)
		);

		echo '<div ' . $this->get_render_attribute_string( 'visual' ) . '>';
		if ( $this->can_display_featured_image( (int) $post_id ) ) {
			echo wp_get_attachment_image(
				get_post_thumbnail_id( $post_id ),
				'hal-bl-listing-card',
				false,
				array( 'class' => 'hal-bl-listing-visual__image' )
			);
		} else {
			echo '<div class="hal-bl-listing-visual__placeholder" aria-hidden="true">';
			echo '<svg viewBox="0 0 64 64" focusable="false">' . $this->get_placeholder_icon( $industry ) . '</svg>';
			echo '</div>';
		}
		echo '</div>';
	}

	private function can_display_featured_image( int $post_id ): bool {
		return has_post_thumbnail( $post_id )
			&& HAL_BL_Display::can_display_public_visual( $post_id );
	}

	private function get_industry_code( int $post_id ): string {
		$value = sanitize_title( (string) get_post_meta( $post_id, 'company_industry', true ) );

		$industries = array(
			'manufacturing',
			'technology',
			'healthcare',
			'food-beverage',
			'logistics',
			'professional-services',
			'real-estate',
			'retail',
		);

		return in_array( $value, $industries, true ) ? $value : 'generic';
	}

	private function get_placeholder_icon( string $industry ): string {
		$icons = array(
			'manufacturing'         => '<path d="M10 52h44M14 52V27l14 8V23l14 7v22M14 27l8-5v9M28 35l8-5v9M22 52V43h8v9M40 52V39h8v13" />',
			'technology'            => '<rect x="9" y="11" width="46" height="31" rx="3" /><path d="M24 53h16M32 42v11M20 31l7-7 7 7M38 31l6-6" />',
			'healthcare'            => '<rect x="11" y="12" width="42" height="40" rx="4" /><path d="M18 33h8l4-9 6 18 4-9h7M27 19h10" />',
			'food-beverage'         => '<path d="M20 12v17M16 12v17M24 12v17M20 29v23M43 12v40M43 12c7 6 7 15 0 20" />',
			'logistics'             => '<path d="M8 18h31v25H8zM39 27h9l8 9v7H39zM17 48a5 5 0 1 0 0-10 5 5 0 0 0 0 10ZM47 48a5 5 0 1 0 0-10 5 5 0 0 0 0 10Z" />',
			'professional-services' => '<path d="M12 52V20h40v32M8 52h48M22 20v-7h20v7M24 31h16M24 39h16M24 47h16" />',
			'real-estate'           => '<path d="M10 52h44M15 52V27l17-13 17 13v25M24 52V38h16v14M25 30h4M35 30h4" />',
			'retail'                => '<path d="M13 24h38l-4 28H17zM10 24l5-11h34l5 11M24 33h16M27 52V40h10v12" />',
			'generic'               => '<path d="M10 50h44M16 50V27h32v23M23 27v-9h18v9M25 35h5M34 35h5M25 43h5M34 43h5" />',
		);

		return $icons[ $industry ] ?? $icons['generic'];
	}
}
