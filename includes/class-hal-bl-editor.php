<?php
declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit; // منع الوصول المباشر للملف
}

/**
 * Card C1 — editor infrastructure for business_listing.
 *
 * Owns every editor-only concern for the Business Listing post type:
 * the native Gutenberg starter template (core blocks only, unlocked),
 * the public-contact meta contracts, the scoped editor assets, and the
 * localized boot data consumed by admin-editor.js (Card C4).
 *
 * Scope contract: each hook below is gated on the business_listing post
 * type (by callback, by subtype, or by admin screen) so nothing runs for
 * posts, pages, or any other post type. Confidential seller values enter
 * the localized boot data only for users passing both edit_post and the
 * existing seller-field capability, and are never registered in REST.
 */
final class HAL_BL_Editor {

	private static bool $bootstrapped = false;

	public static function bootstrap(): void {
		if ( self::$bootstrapped ) {
			return;
		}
		self::$bootstrapped = true;

		add_action( 'init', array( __CLASS__, 'register_public_contact_meta' ) );
		add_filter( 'register_post_type_args', array( __CLASS__, 'apply_starter_template' ), 10, 2 );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_editor_assets' ) );
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_routes' ) );
	}

	/**
	 * Card C1 (post-C7 correction, 2nd round) — the editor's gallery write
	 * channel. `business_listing` deliberately does not support
	 * custom-fields (raw custom-field boxes could surface sensitive meta),
	 * so core REST would silently ignore any `meta` payload for this type.
	 * The gallery therefore uses a dedicated route guarded by edit_post —
	 * the proven pattern of the seller-contact route — while storage stays
	 * the canonical `company_gallery` key with the classic validation.
	 */
	public static function sanitize_gallery_ids( $value ): array {
		if ( ! is_array( $value ) ) {
			return array();
		}

		$ids = array();
		foreach ( $value as $raw_id ) {
			$id = absint( $raw_id );
			if ( $id <= 0 || in_array( $id, $ids, true ) ) {
				continue;
			}
			if ( current_user_can( 'edit_post', $id ) && 'attachment' === get_post_type( $id ) && wp_attachment_is_image( $id ) ) {
				$ids[] = $id;
			}
		}

		return $ids;
	}

	public static function register_rest_routes(): void {
		register_rest_route(
			'hal-business-listings/v1',
			'/business-listing/(?P<id>\d+)/gallery',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( __CLASS__, 'handle_gallery_update' ),
				'permission_callback' => array( __CLASS__, 'gallery_permissions' ),
				'args'                => array(
					'ids' => array(
						'type'              => 'array',
						'required'          => true,
						'items'             => array( 'type' => 'integer' ),
						'sanitize_callback' => array( __CLASS__, 'sanitize_gallery_ids' ),
					),
				),
			)
		);

		register_rest_route(
			'hal-business-listings/v1',
			'/business-listing/(?P<id>\d+)/seller-contact',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( __CLASS__, 'handle_seller_contact_update' ),
				'permission_callback' => array( __CLASS__, 'seller_contact_permissions' ),
				'args'                => array(
					'name'  => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'phone' => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'email' => array(
						'type'              => 'string',
						'required'          => true,
						'sanitize_callback' => 'sanitize_email',
					),
				),
			)
		);
	}

	/**
	 * edit_post on the listing — the same boundary the classic gallery
	 * save path and the ACF canvas enforce.
	 */
	public static function gallery_permissions( WP_REST_Request $request ): bool {
		$id = absint( $request->get_param( 'id' ) );
		// Type boundary: the classic save paths were bound to the
		// save_post_business_listing hook; the REST route enforces it itself.
		return $id > 0
			&& 'business_listing' === get_post_type( $id )
			&& current_user_can( 'edit_post', $id );
	}

	/**
	 * Nonce enforced on top of REST cookie authentication; storage is the
	 * canonical `company_gallery` key (empty array deletes, matching the
	 * classic path's semantics).
	 */
	public static function handle_gallery_update( WP_REST_Request $request ) {
		$nonce = $request->get_header( 'X-WP-Nonce' );
		if ( ! $nonce || ! wp_verify_nonce( $nonce, 'wp_rest' ) ) {
			return new WP_Error(
				'hal_bl_rest_nonce_failed',
				__( 'Session verification failed. Please reload the editor and try again.', 'hal-business-listings' ),
				array( 'status' => 403 )
			);
		}

		$id = absint( $request->get_param( 'id' ) );
		if ( ! current_user_can( 'edit_post', $id ) ) {
			return new WP_Error(
				'hal_bl_rest_forbidden',
				__( 'You are not allowed to edit this listing.', 'hal-business-listings' ),
				array( 'status' => 403 )
			);
		}

		$ids = self::sanitize_gallery_ids( (array) $request->get_param( 'ids' ) );
		if ( empty( $ids ) ) {
			delete_post_meta( $id, 'company_gallery' );
		} else {
			update_post_meta( $id, 'company_gallery', $ids );
		}

		return rest_ensure_response( array( 'updated' => true, 'ids' => $ids ) );
	}

	/**
	 * Dual capability gate mirroring hal_bl_save_sensitive_seller_data():
	 * edit_post on the listing AND the existing seller-field capability.
	 */
	public static function seller_contact_permissions( WP_REST_Request $request ): bool {
		$id = absint( $request->get_param( 'id' ) );
		// Type boundary: the classic save paths were bound to the
		// save_post_business_listing hook; the REST route enforces it itself.
		return $id > 0
			&& 'business_listing' === get_post_type( $id )
			&& current_user_can( 'edit_post', $id )
			&& current_user_can( self::seller_capability() );
	}

	/**
	 * Nonce enforced on top of REST cookie authentication, plus a clean
	 * copy of the retired path's storage semantics (empty deletes).
	 */
	public static function handle_seller_contact_update( WP_REST_Request $request ) {
		$nonce = $request->get_header( 'X-WP-Nonce' );
		if ( ! $nonce || ! wp_verify_nonce( $nonce, 'wp_rest' ) ) {
			return new WP_Error(
				'hal_bl_rest_nonce_failed',
				__( 'Session verification failed. Please reload the editor and try again.', 'hal-business-listings' ),
				array( 'status' => 403 )
			);
		}

		$id     = absint( $request->get_param( 'id' ) );
		$fields = array(
			'_hal_bl_seller_contact_name'  => (string) $request->get_param( 'name' ),
			'_hal_bl_seller_contact_phone' => (string) $request->get_param( 'phone' ),
			'_hal_bl_seller_contact_email' => (string) $request->get_param( 'email' ),
		);

		foreach ( $fields as $meta_key => $value ) {
			if ( '' === $value ) {
				delete_post_meta( $id, $meta_key );
			} else {
				update_post_meta( $id, $meta_key, $value );
			}
		}

		return rest_ensure_response(
			array(
				'updated' => true,
				'name'    => $fields['_hal_bl_seller_contact_name'],
				'phone'   => $fields['_hal_bl_seller_contact_phone'],
				'email'   => $fields['_hal_bl_seller_contact_email'],
			)
		);
	}

	/**
	 * Card 4A approved keys with explicit contracts: string type, single
	 * value, per-key sanitization for REST writes, and edit_post-gated
	 * authorization. Restricted seller keys are deliberately absent.
	 */
	public static function register_public_contact_meta(): void {
		$contracts = array(
			'_hal_bl_public_phone'   => array(
				'sanitize_callback' => 'hal_bl_sanitize_phone_like',
				'description'      => __( 'Public business phone number (phone-like string).', 'hal-business-listings' ),
			),
			'_hal_bl_public_email'   => array(
				'sanitize_callback' => 'sanitize_email',
				'description'      => __( 'Public business email address.', 'hal-business-listings' ),
			),
			'_hal_bl_public_website' => array(
				'sanitize_callback' => 'esc_url_raw',
				'description'      => __( 'Public business website URL.', 'hal-business-listings' ),
			),
		);

		foreach ( $contracts as $meta_key => $contract ) {
			register_post_meta(
				'business_listing',
				$meta_key,
				array(
					'type'              => 'string',
					'single'            => true,
					'sanitize_callback' => $contract['sanitize_callback'],
					'auth_callback'     => array( __CLASS__, 'authorize_meta_edit' ),
					'show_in_rest'      => array(
						'schema' => array(
							'type'        => 'string',
							'description' => $contract['description'],
							'context'     => array( 'view', 'edit' ),
							'required'    => false,
						),
					),
				)
			);
		}
	}

	public static function authorize_meta_edit( bool $allowed, string $meta_key, int $object_id, int $user_id, string $cap, array $caps ): bool {
		return user_can( $user_id, 'edit_post', $object_id );
	}

	/**
	 * Native starter template for new listings: one core paragraph. Core
	 * blocks only; template_lock stays unset (unlocked) as required.
	 * Existing posts are unaffected — templates seed new content only.
	 */
	public static function apply_starter_template( array $args, string $post_type ): array {
		if ( 'business_listing' !== $post_type ) {
			return $args;
		}

		$args['template'] = array(
			array(
				'core/paragraph',
				array(
					'placeholder' => __( 'Describe the business activity using blocks…', 'hal-business-listings' ),
				),
			),
		);

		return $args;
	}

	public static function enqueue_editor_assets( string $hook ): void {
		if ( ! in_array( $hook, array( 'post.php', 'post-new.php' ), true ) ) {
			return;
		}

		$screen = get_current_screen();
		if ( ! $screen || 'business_listing' !== $screen->post_type ) {
			return;
		}

		wp_enqueue_media();

		wp_enqueue_style(
			'hal-business-listings-admin-editor',
			plugin_dir_url( HAL_BL_FILE ) . 'assets/css/admin-editor.css',
			array(),
			self::asset_version( 'assets/css/admin-editor.css' )
		);

		wp_enqueue_script(
			'hal-business-listings-admin-editor',
			plugin_dir_url( HAL_BL_FILE ) . 'assets/js/admin-editor.js',
			array( 'wp-edit-post', 'wp-data', 'wp-components', 'wp-element', 'wp-i18n', 'wp-plugins', 'wp-blocks' ),
			self::asset_version( 'assets/js/admin-editor.js' ),
			true
		);

		wp_set_script_translations( 'hal-business-listings-admin-editor', 'hal-business-listings', plugin_dir_path( HAL_BL_FILE ) . 'languages' );

		wp_localize_script(
			'hal-business-listings-admin-editor',
			'halBlEditor',
			self::build_boot_data( get_post() )
		);
	}

	/**
	 * The exact boot contract admin-editor.js (C4) consumes. Seller values
	 * are included only for users passing edit_post AND the seller-field
	 * capability; otherwise the panel stays hidden (fail-closed in JS).
	 */
	private static function build_boot_data( ?WP_Post $post ): array {
		$data = array(
			'sellerPanelAllowed' => false,
			'sellerValues'       => null,
			'galleryItems'       => array(),
			'restNonce'          => '',
			'sellerRoute'        => '',
			'galleryRoute'       => '',
		);

		// New-listing screens have no post yet; REST values need a post ID.
		if ( ! $post instanceof WP_Post ) {
			return $data;
		}

		$data['restNonce']   = wp_create_nonce( 'wp_rest' );
		$data['sellerRoute'] = rest_url( 'hal-business-listings/v1/business-listing/' . $post->ID . '/seller-contact' );
		$data['galleryRoute'] = rest_url( 'hal-business-listings/v1/business-listing/' . $post->ID . '/gallery' );

		$seller_allowed = current_user_can( 'edit_post', $post->ID )
			&& current_user_can( self::seller_capability() );

		$data['sellerPanelAllowed'] = $seller_allowed;

		if ( $seller_allowed ) {
			$data['sellerValues'] = array(
				'name'  => (string) get_post_meta( $post->ID, '_hal_bl_seller_contact_name', true ),
				'phone' => (string) get_post_meta( $post->ID, '_hal_bl_seller_contact_phone', true ),
				'email' => (string) get_post_meta( $post->ID, '_hal_bl_seller_contact_email', true ),
			);
		}

		$gallery_ids = get_post_meta( $post->ID, 'company_gallery', true );
		if ( is_array( $gallery_ids ) ) {
			foreach ( $gallery_ids as $attachment_id ) {
				$attachment_id = absint( $attachment_id );
				if ( $attachment_id <= 0 ) {
					continue;
				}

				$thumbnail = wp_get_attachment_image_src( $attachment_id, 'thumbnail' );
				$url        = is_array( $thumbnail ) && ! empty( $thumbnail[0] )
					? (string) $thumbnail[0]
					: (string) wp_get_attachment_url( $attachment_id );

				$data['galleryItems'][] = array(
					'id'  => $attachment_id,
					'url' => $url,
				);
			}
		}

		return $data;
	}

	/**
	 * The seller-field capability lives in class-hal-bl-listings.php; this
	 * fallback keeps the same filter default if that file is ever absent.
	 */
	private static function seller_capability(): string {
		if ( function_exists( 'hal_bl_seller_field_capability' ) ) {
			return hal_bl_seller_field_capability();
		}

		return (string) apply_filters( 'hal_bl_seller_field_capability', 'manage_hal_bl_sensitive_data' );
	}

	private static function asset_version( string $relative_path ): string {
		$path = plugin_dir_path( HAL_BL_FILE ) . $relative_path;
		return is_readable( $path ) ? (string) filemtime( $path ) : HAL_BL_VERSION;
	}
}

HAL_BL_Editor::bootstrap();
