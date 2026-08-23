<?php
declare(strict_types=1);
defined( 'ABSPATH' ) || exit;

function hal_bl_register_elementor_listing_visual_widget( $widgets_manager ): void {
	if ( ! class_exists( '\\Elementor\\Widget_Base' ) ) return;
	require_once plugin_dir_path( HAL_BL_FILE ) . 'class-hal-bl-elementor-listing-visual-widget.php';
	$widgets_manager->register( new HAL_BL_Elementor_Listing_Visual_Widget() );
}
add_action( 'elementor/widgets/register', 'hal_bl_register_elementor_listing_visual_widget' );

/**
 * Public listing fields only; seller fields are deliberately never registered.
 * The dynamic-tags editing UI requires Elementor Pro — registration stays
 * guarded so installs without the Dynamic Tags module never fatal.
 */
function hal_bl_register_elementor_dynamic_tags( $manager ): void {
	if ( ! class_exists( '\\Elementor\\Core\\DynamicTags\\Tag' ) || ! ( $manager instanceof \Elementor\Core\DynamicTags\Manager ) ) return;
	$manager->register_group( 'hal-business-listings', array( 'title' => __( 'Business Listings', 'hal-business-listings' ) ) );
	if ( ! class_exists( 'HAL_BL_Elementor_Public_Field_Tag', false ) ) {
		class HAL_BL_Elementor_Public_Field_Tag extends \Elementor\Core\DynamicTags\Tag {
			private string $field = '';
			public function set_field( string $field ): self { $this->field = $field; return $this; }
			public function get_name(): string { return 'hal-bl-' . $this->field; }
			public function get_title(): string { return ucwords( str_replace( '_', ' ', $this->field ) ); }
			public function get_group(): array { return array( 'hal-business-listings' ); }
			public function get_categories(): array { return array( \Elementor\Modules\DynamicTags\Module::TEXT_CATEGORY ); }
			public function render(): void { $fields = HAL_BL_Display::public_fields( (int) get_the_ID() ); $value = $fields[ $this->field ] ?? ''; if ( is_array( $value ) ) $value = implode( ', ', $value ); echo esc_html( (string) $value ); }
		}
	}
	foreach ( array( 'reference', 'country', 'city', 'industry', 'legal_form', 'year', 'employees', 'price_mode', 'price_range', 'status' ) as $field ) $manager->register( ( new HAL_BL_Elementor_Public_Field_Tag() )->set_field( $field ) );
}
add_action( 'elementor/dynamic_tags/register', 'hal_bl_register_elementor_dynamic_tags' );
