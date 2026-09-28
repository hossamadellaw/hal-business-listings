<?php
declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit; // منع الوصول المباشر للملف
}

/**
 * 0.b) نقطة تحكم واحدة لاسم رابط الأرشيف — مصدر واحد للحقيقة
 * يُستخدم في تسجيل الـ CPT وتسجيل تصنيف الدولة معًا، لضمان
 * تطابق الروابط دائمًا حتى لو غُيّر عبر الفلتر مستقبلًا.
 */
function hal_bl_get_archive_slug(): string {
	$slug = sanitize_title( (string) apply_filters( 'hal_bl_archive_slug', 'companies-for-sale' ) );
	return '' !== $slug ? $slug : 'companies-for-sale';
}

/**
 * Keep a context page as a post ID, never as a stored URL. WordPress then
 * follows permalink changes and WPML can resolve the translated page safely.
 */
function hal_bl_sanitize_context_page_id( $value ): int {
	$page_id = absint( $value );
	if ( 0 === $page_id ) {
		return 0;
	}

	return 'page' === get_post_type( $page_id ) && 'publish' === get_post_status( $page_id ) ? $page_id : 0;
}

function hal_bl_register_context_page_setting(): void {
	register_setting(
		'hal_bl_listing_settings_group',
		'hal_bl_context_page_id',
		array(
			'type'              => 'integer',
			'sanitize_callback' => 'hal_bl_sanitize_context_page_id',
			'default'           => 0,
		)
	);
}
add_action( 'admin_init', 'hal_bl_register_context_page_setting' );

function hal_bl_add_listing_settings_page(): void {
	add_submenu_page(
		'edit.php?post_type=business_listing',
		__( 'Listing Settings', 'hal-business-listings' ),
		__( 'Listing Settings', 'hal-business-listings' ),
		'manage_options',
		'hal-bl-listing-settings',
		'hal_bl_render_listing_settings_page'
	);
}
add_action( 'admin_menu', 'hal_bl_add_listing_settings_page' );

function hal_bl_get_context_page_id(): int {
	return hal_bl_sanitize_context_page_id( get_option( 'hal_bl_context_page_id', 0 ) );
}

function hal_bl_get_context_page_url(): string {
	$page_id = hal_bl_get_context_page_id();
	if ( 0 === $page_id ) {
		return '';
	}

	$current_language = apply_filters( 'wpml_current_language', null );
	if ( is_string( $current_language ) && '' !== $current_language ) {
		$translated_id = apply_filters( 'wpml_object_id', $page_id, 'page', false, $current_language );
		if ( is_numeric( $translated_id ) && (int) $translated_id > 0 ) {
			$page_id = (int) $translated_id;
		}
	}

	$url = get_permalink( $page_id );
	return is_string( $url ) ? $url : '';
}

function hal_bl_context_link_shortcode( $atts ): string {
	$url = hal_bl_get_context_page_url();
	if ( '' === $url ) {
		return '';
	}

	$atts  = shortcode_atts( array( 'label' => __( 'Companies Practice Area', 'hal-business-listings' ) ), $atts, 'hal_bl_context_link' );
	$label = sanitize_text_field( (string) $atts['label'] );

	return sprintf( '<a href="%1$s" class="hal-bl-context-link">%2$s</a>', esc_url( $url ), esc_html( $label ) );
}
add_shortcode( 'hal_bl_context_link', 'hal_bl_context_link_shortcode' );

function hal_bl_render_listing_settings_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Business Listings Settings', 'hal-business-listings' ); ?></h1>
		<p><?php esc_html_e( 'Select the published practice-area page that provides context for listings. The plugin stores its ID, not a brittle URL.', 'hal-business-listings' ); ?></p>
		<form action="options.php" method="post">
			<?php settings_fields( 'hal_bl_listing_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="hal-bl-context-page-id"><?php esc_html_e( 'Companies context page', 'hal-business-listings' ); ?></label></th>
					<td>
						<?php
						wp_dropdown_pages(
							array(
								'name'              => 'hal_bl_context_page_id',
								'id'                => 'hal-bl-context-page-id',
								'selected'          => hal_bl_get_context_page_id(),
								'show_option_none'  => __( '— No context page —', 'hal-business-listings' ),
								'option_none_value' => '0',
								'post_status'       => 'publish',
							)
						);
						?>
						<p class="description"><?php esc_html_e( 'WPML resolves the translated page automatically. Use [hal_bl_context_link] in an Elementor Shortcode widget when a contextual link is needed.', 'hal-business-listings' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button(); ?>
		</form>

		<?php
		$pending     = get_option( 'hal_bl_visual_policy_pending', array() );
		$pending     = is_array( $pending ) ? array_map( 'absint', $pending ) : array();
		$live_pending = array_filter( $pending, 'hal_bl_visual_policy_needs_review' );
		$applied      = isset( $_GET['hal_bl_visual_policy'] ) && 'applied' === sanitize_key( wp_unslash( $_GET['hal_bl_visual_policy'] ) );
		?>
		<hr />
		<h2><?php esc_html_e( 'Visual Policy Review', 'hal-business-listings' ); ?></h2>
		<p><?php esc_html_e( 'Listings below have visual media but no explicit public-approval decision. Nothing is removed automatically; applying the policy removes their featured image and gallery associations and keeps a restore backup in post meta.', 'hal-business-listings' ); ?></p>
		<?php if ( $applied ) : ?>
			<div class="notice notice-success"><p><?php esc_html_e( 'Visual policy applied; unapproved associations were removed with a backup.', 'hal-business-listings' ); ?></p></div>
		<?php endif; ?>
		<?php if ( empty( $live_pending ) ) : ?>
			<p><?php esc_html_e( 'No listings awaiting visual review.', 'hal-business-listings' ); ?></p>
		<?php else : ?>
			<p>
				<?php
				printf(
					esc_html( _n( '%d listing awaits visual review.', '%d listings await visual review.', count( $live_pending ), 'hal-business-listings' ) ),
					(int) count( $live_pending )
				);
				?>
			</p>
			<ul>
				<?php foreach ( $live_pending as $review_id ) : ?>
					<li><a href="<?php echo esc_url( (string) get_edit_post_link( $review_id ) ); ?>"><?php echo esc_html( (string) get_the_title( $review_id ) ); ?></a></li>
				<?php endforeach; ?>
			</ul>
			<form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post">
				<input type="hidden" name="action" value="hal_bl_apply_visual_policy" />
				<?php wp_nonce_field( 'hal_bl_apply_visual_policy' ); ?>
				<?php submit_button( __( 'Apply policy to listed items', 'hal-business-listings' ), 'delete' ); ?>
			</form>
		<?php endif; ?>
	</div>
	<?php
}

/**
 * 0.c) الصلاحية المطلوبة لرؤية/تعديل بيانات البائع الحساسة —
 * قابلة للتخصيص بفلتر بدل تعديل الكود مباشرة.
 */
function hal_bl_seller_field_capability(): string {
	return (string) apply_filters( 'hal_bl_seller_field_capability', 'manage_hal_bl_sensitive_data' );
}

/**
 * 0.d) قائمة الدول الافتراضية — قابلة للتوسيع بفلتر.
 */
function hal_bl_default_countries(): array {
	return (array) apply_filters(
		'hal_bl_default_countries',
		array( 'Egypt', 'Saudi Arabia', 'United Arab Emirates', 'Germany', 'Other' )
	);
}

/**
 * Explicit capabilities keep deal data separate from ordinary editorial work.
 * Administrators receive them on activation and upgrade; other roles must be
 * granted them deliberately by the site owner.
 */
function hal_bl_listing_capabilities(): array {
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
	);
}

function hal_bl_grant_administrator_capabilities(): void {
	$administrator = get_role( 'administrator' );
	if ( ! $administrator ) {
		return;
	}

	// Classify every candidate capability at its first grant by this
	// plugin: a name already on the role pre-dated HAL and is protected
	// from uninstall cleanup; a name absent here is introduced by this
	// grant and recorded for removal. Classifications never change after
	// their first entry.
	$ledger = (array) get_option( 'hal_bl_capabilities_ledger', array() );
	$seller_capability = (string) hal_bl_seller_field_capability();
	$candidates = array_merge( hal_bl_listing_capabilities(), array( $seller_capability ) );
	$dirty = false;
	foreach ( $candidates as $candidate ) {
		if ( array_key_exists( $candidate, $ledger ) ) {
			continue;
		}
		$ledger[ $candidate ] = array_key_exists( $candidate, $administrator->capabilities ) ? 'pre_existing' : 'granted';
		$dirty = true;
	}
	if ( $dirty ) {
		update_option( 'hal_bl_capabilities_ledger', $ledger, false );
	}

	foreach ( hal_bl_listing_capabilities() as $capability ) {
		$administrator->add_cap( $capability );
	}

	$administrator->add_cap( $seller_capability );
}

/** Keep integration secrets and diagnostic state out of WordPress autoload. */
function hal_bl_initialize_plugin_options(): void {
	// add_option() is a no-op for existing sites. Calling it directly avoids
	// register_setting's default-value filter making a missing option appear set.
	add_option( 'hal_bl_amelia_settings', hal_bl_amelia_settings_defaults(), '', 'no' );
	add_option( 'hal_bl_amelia_event_log', array(), '', 'no' );
	add_option( 'hal_bl_amelia_health', array(), '', 'no' );
}


/**
 * 1) تسجيل نوع المحتوى: business_listing
 */
if ( ! function_exists( 'hal_register_business_listing_cpt' ) ) :
	function hal_register_business_listing_cpt(): void {

		$labels = array(
			'name'               => __( 'Business Listings', 'hal-business-listings' ),
			'singular_name'      => __( 'Business Listing', 'hal-business-listings' ),
			'menu_name'          => __( 'Business Listings', 'hal-business-listings' ),
			'add_new'            => __( 'Add New Listing', 'hal-business-listings' ),
			'add_new_item'       => __( 'Add New Business Listing', 'hal-business-listings' ),
			'edit_item'          => __( 'Edit Business Listing', 'hal-business-listings' ),
			'new_item'           => __( 'New Business Listing', 'hal-business-listings' ),
			'view_item'          => __( 'View Listing', 'hal-business-listings' ),
			'view_items'         => __( 'View Listings', 'hal-business-listings' ),
			'search_items'       => __( 'Search Listings', 'hal-business-listings' ),
			'not_found'          => __( 'No listings found', 'hal-business-listings' ),
			'not_found_in_trash' => __( 'No listings found in Trash', 'hal-business-listings' ),
			'all_items'          => __( 'All Listings', 'hal-business-listings' ),
			'archives'           => __( 'Listing Archives', 'hal-business-listings' ),
			'attributes'         => __( 'Listing Attributes', 'hal-business-listings' ),
		);

		$args = array(
			'labels'             => $labels,
			'public'             => true,
			'publicly_queryable' => true,
			'show_ui'            => true,
			'show_in_menu'       => true,
			'show_in_rest'       => true, // للتوافق مع Elementor / Gutenberg
			'menu_position'      => 26,
			'menu_icon'          => 'dashicons-building',
			'capability_type'    => array( 'business_listing', 'business_listings' ),
			'map_meta_cap'       => true,
			'hierarchical'       => false,
			'supports'           => array( 'title', 'editor', 'thumbnail', 'excerpt' ), // Custom Fields الخام قد يكشف metadata حساسة.
			'has_archive'        => hal_bl_get_archive_slug(),
			'rewrite'            => array(
				'slug'       => hal_bl_get_archive_slug(),
				'with_front' => false,
			),
			'query_var'          => true,
		);

		register_post_type( 'business_listing', $args );
	}
endif;
add_action( 'init', 'hal_register_business_listing_cpt' );


/**
 * 1.b) تصنيف "الدولة" — Taxonomy حقيقية بدل select ثابت
 * بتدي رابط أرشيف مفلتر تلقائي: companies-for-sale/country/egypt/
 */
if ( ! function_exists( 'hal_register_listing_country_taxonomy' ) ) :
	function hal_register_listing_country_taxonomy(): void {

		register_taxonomy(
			'listing_country',
			array( 'business_listing' ),
			array(
				'labels'            => array(
					'name'          => __( 'Countries', 'hal-business-listings' ),
					'singular_name' => __( 'Country', 'hal-business-listings' ),
					'menu_name'     => __( 'Country', 'hal-business-listings' ),
				),
				'hierarchical'      => false, // اختيار واحد بسيط، مش تصنيف أب/ابن
				'public'            => true,
				'show_ui'           => true,
				'show_admin_column' => true,
				'show_in_rest'      => true,
				'meta_box_cb'       => false,
				'rewrite'           => array(
					'slug'       => hal_bl_get_archive_slug() . '/country',
					'with_front' => false,
				),
			)
		);
	}
endif;
add_action( 'init', 'hal_register_listing_country_taxonomy' );


/**
 * 1.c) تعبئة الدول الافتراضية — مرة واحدة حقيقية فقط
 * علم دائم في wp_options بدل تشغيل term_exists() في كل تحميل
 * صفحة على الموقع بأكمله (تحسين أداء مباشر: من 5 استعلامات في
 * كل طلب، إلى قراءة option واحدة مؤقّتة الذاكرة).
 */
/**
 * Batch locks carry a TTL so an interrupted run cannot block retries forever.
 * A fresh lock is always respected; an expired one is recovered and logged
 * with a non-sensitive status code only.
 */
function hal_bl_acquire_lock( string $lock ): bool {
	$locked_at = (int) get_option( $lock, 0 );
	if ( $locked_at && $locked_at > time() - 15 * MINUTE_IN_SECONDS ) {
		return false;
	}

	if ( $locked_at ) {
		error_log( 'HAL Business Listings expired lock recovered: ' . sanitize_key( $lock ) );
		delete_option( $lock );
	}

	return add_option( $lock, time(), '', 'no' );
}

if ( ! function_exists( 'hal_bl_seed_listing_countries' ) ) :
	function hal_bl_seed_listing_countries(): bool {
		if ( ! hal_bl_acquire_lock( 'hal_bl_country_seed_lock' ) ) {
			return false;
		}

		$seeded = true;
		foreach ( hal_bl_default_countries() as $country ) {
			if ( ! term_exists( $country, 'listing_country' ) ) {
				$result = wp_insert_term( $country, 'listing_country' );
				if ( is_wp_error( $result ) ) {
					$seeded = false;
					error_log( 'HAL Business Listings country seed failed: ' . sanitize_key( $result->get_error_code() ) );
					break;
				}
			}
		}

		delete_option( 'hal_bl_country_seed_lock' );
		return $seeded;
	}
endif;

if ( ! function_exists( 'hal_bl_maybe_seed_listing_countries' ) ) :
function hal_bl_maybe_seed_listing_countries(): void {
		if ( get_option( 'hal_bl_countries_seeded' ) ) {
			return; // لا استعلامات إضافية بعد أول مرة إطلاقًا
		}

		if ( hal_bl_seed_listing_countries() ) {
			update_option( 'hal_bl_countries_seeded', 1 );
		}
	}
endif;
// شبكة أمان تلقائية (self-healing): تعمل فقط لو العلم مفقود لأي سبب،
// وليس في كل تحميل صفحة كما كان سابقًا.
add_action( 'init', 'hal_bl_maybe_seed_listing_countries', 20 );

/**
 * Move legacy ACF seller fields into protected meta keys. The old keys are
 * deliberately removed only after their values have been copied, so the core
 * Custom Fields UI can no longer expose them to ordinary listing editors.
 */
function hal_bl_migrate_sensitive_seller_data(): bool {
	global $wpdb;

	if ( ! hal_bl_acquire_lock( 'hal_bl_seller_migration_lock' ) ) {
		return false;
	}

	$legacy_to_protected = array(
		'seller_contact_name'  => '_hal_bl_seller_contact_name',
		'seller_contact_phone' => '_hal_bl_seller_contact_phone',
		'seller_contact_email' => '_hal_bl_seller_contact_email',
	);

	$cursor   = absint( get_option( 'hal_bl_seller_migration_cursor', 0 ) );
	$batch    = 50;
	$listings = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->posts} WHERE post_type = %s AND ID > %d ORDER BY ID ASC LIMIT %d", 'business_listing', $cursor, $batch ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

	foreach ( $listings as $listing_id ) {
			foreach ( $legacy_to_protected as $legacy_key => $protected_key ) {
				$legacy_value = get_post_meta( $listing_id, $legacy_key, true );
				if ( '' === $legacy_value ) {
					continue;
				}

				$protected_value = get_post_meta( $listing_id, $protected_key, true );
				if ( '' !== $protected_value && $protected_value !== $legacy_value ) {
					$conflicts = get_post_meta( $listing_id, '_hal_bl_seller_migration_conflict_fields', true );
					$conflicts = is_array( $conflicts ) ? $conflicts : array();
					$conflicts[] = $legacy_key; // Field name only — no PII values recorded.
					update_post_meta( $listing_id, '_hal_bl_seller_migration_conflict_fields', array_unique( $conflicts ) );
					continue; // Keep both values until an administrator resolves the conflict.
				}

				if ( '' === $protected_value && false === update_post_meta( $listing_id, $protected_key, $legacy_value ) ) {
					delete_option( 'hal_bl_seller_migration_lock' );
					return false;
				}

				delete_post_meta( $listing_id, $legacy_key );
				delete_post_meta( $listing_id, '_' . $legacy_key );
			}
			$cursor = (int) $listing_id;
			update_option( 'hal_bl_seller_migration_cursor', $cursor, false );
		}

	delete_option( 'hal_bl_seller_migration_lock' );
	if ( count( $listings ) < $batch ) {
		delete_option( 'hal_bl_seller_migration_cursor' );
		return true;
	}

	return false;
}

function hal_bl_run_upgrade(): void {
	if ( HAL_BL_SCHEMA_VERSION === get_option( 'hal_bl_schema_version' ) ) {
		return;
	}

	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	hal_bl_grant_administrator_capabilities();
	hal_bl_initialize_plugin_options();
	if ( hal_bl_migrate_sensitive_seller_data() && hal_bl_review_public_visuals_batch() ) {
		update_option( 'hal_bl_schema_version', HAL_BL_SCHEMA_VERSION );
	}
}
add_action( 'admin_init', 'hal_bl_run_upgrade' );


/**
 * 1.d) تفعيل الأرشيف تلقائيًا وقت تنشيط الإضافة — بدون خطوة
 * يدوية في Settings → Permalinks.
 */
function hal_bl_activate_site(): void {
	hal_register_business_listing_cpt();
	hal_register_listing_country_taxonomy();
	if ( hal_bl_seed_listing_countries() ) {
		update_option( 'hal_bl_countries_seeded', 1 );
	}
	hal_bl_grant_administrator_capabilities();
	hal_bl_initialize_plugin_options();
	flush_rewrite_rules();
}

/**
 * Activates the plugin for the current site or for every site in a network-wide activation.
 *
 * @param bool $network_wide Whether the plugin is being activated network-wide.
 */
function hal_bl_on_activate( bool $network_wide ): void {
	if ( ! is_multisite() || ! $network_wide ) {
		hal_bl_activate_site();
		return;
	}

	$site_ids = get_sites( array( 'fields' => 'ids' ) );
	foreach ( $site_ids as $site_id ) {
		switch_to_blog( (int) $site_id );
		hal_bl_activate_site();
		restore_current_blog();
	}
}

function hal_bl_deactivate_site(): void {
	wp_clear_scheduled_hook( HAL_BL_AMELIA_SYNC_HOOK );
	delete_transient( HAL_BL_AMELIA_CATALOG_TRANSIENT );
	delete_transient( HAL_BL_AMELIA_ERROR_TRANSIENT );
	flush_rewrite_rules();
}

/**
 * Deactivates the plugin for the current site or for every site in a network-wide deactivation.
 *
 * @param bool $network_wide Whether the plugin is being deactivated network-wide.
 */
function hal_bl_on_deactivate( bool $network_wide ): void {
	if ( ! is_multisite() || ! $network_wide ) {
		hal_bl_deactivate_site();
		return;
	}

	$site_ids = get_sites( array( 'fields' => 'ids' ) );
	foreach ( $site_ids as $site_id ) {
		switch_to_blog( (int) $site_id );
		hal_bl_deactivate_site();
		restore_current_blog();
	}
}


/**
 * 2) حقول ACF — القايمة المتفق عليها كبداية
 */
function hal_bl_register_acf_fields(): void {
	if ( ! function_exists( 'acf_add_local_field_group' ) ) {
		return;
	}

	acf_add_local_field_group(
		array(
			'key'      => 'group_business_listing_public',
			'title'    => __( 'Basic business information', 'hal-business-listings' ),
			'fields'   => array(

				array(
					'key'          => 'field_bl_reference',
					'label'        => __( 'Company Reference / Name', 'hal-business-listings' ),
					'name'         => 'company_reference',
					'type'         => 'text',
					'instructions' => __( 'استخدم كود بدل الاسم الحقيقي لو الشركة طلبت السرية (مثال: EG-CAI-2026-014)', 'hal-business-listings' ),
					'required'     => 1,
				),

				array(
					'key'           => 'field_bl_country',
					'label'         => __( 'Country', 'hal-business-listings' ),
					'name'          => 'company_country',
					'type'          => 'taxonomy',
					'taxonomy'      => 'listing_country',
					'field_type'    => 'select',
					'add_term'      => 0, // منع المحررين من إضافة دول جديدة عشوائيًا
					'save_terms'    => 1,
					'load_terms'    => 1,
					'return_format' => 'id',
					'multiple'      => 0,
					'allow_null'    => 0,
					'required'      => 1,
				),

				array(
					'key'   => 'field_bl_city',
					'label' => __( 'City', 'hal-business-listings' ),
					'name'  => 'company_city',
					'type'  => 'text',
				),

				array(
					'key'           => 'field_bl_industry',
					'label'         => __( 'Industry / Business Activity', 'hal-business-listings' ),
					'name'          => 'company_industry',
					'type'          => 'select',
					'choices'       => array(
						'manufacturing'        => __( 'Manufacturing', 'hal-business-listings' ),
						'technology'           => __( 'Technology', 'hal-business-listings' ),
						'healthcare'           => __( 'Healthcare', 'hal-business-listings' ),
						'food-beverage'        => __( 'Food & Beverage', 'hal-business-listings' ),
						'logistics'            => __( 'Logistics', 'hal-business-listings' ),
						'professional-services' => __( 'Professional Services', 'hal-business-listings' ),
						'real-estate'          => __( 'Real Estate', 'hal-business-listings' ),
						'retail'               => __( 'Retail', 'hal-business-listings' ),
					),
					'return_format' => 'label',
					'required'      => 1,
				),

				array(
					'key'           => 'field_bl_public_visual_approved',
					'label'         => __( 'Public visual approved', 'hal-business-listings' ),
					'name'          => 'public_visual_approved',
					'type'          => 'true_false',
					'default_value' => 0,
					'ui'            => 1,
					'instructions'  => __( 'Enable only when the featured image is approved for public disclosure. Otherwise, the public listing uses a confidential sector placeholder.', 'hal-business-listings' ),
				),

				array(
					'key'          => 'field_bl_legal_form',
					'label'        => __( 'Legal Form', 'hal-business-listings' ),
					'name'         => 'legal_form',
					'type'         => 'text',
					'instructions' => __( 'مثال: LLC, JSC, Sole Proprietorship, GmbH...', 'hal-business-listings' ),
				),

				array(
					'key'   => 'field_bl_year',
					'label' => __( 'Year Established', 'hal-business-listings' ),
					'name'  => 'year_established',
					'type'  => 'number',
					'min'   => 1800,
					'max'   => (int) gmdate( 'Y' ),
				),

				array(
					'key'     => 'field_bl_employees',
					'label'   => __( 'Number of Employees', 'hal-business-listings' ),
					'name'    => 'employee_count',
					'type'    => 'select',
					'choices' => array(
						'1-10'   => '1–10',
						'11-50'  => '11–50',
						'51-200' => '51–200',
						'200+'   => '200+',
					),
				),

				array(
					'key'           => 'field_bl_price_mode',
					'label'         => __( 'Price Display', 'hal-business-listings' ),
					'name'          => 'price_display_mode',
					'type'          => 'radio',
					'choices'       => array(
						'request' => __( 'Request Price', 'hal-business-listings' ),
						'range'   => __( 'Show Price Range', 'hal-business-listings' ),
					),
					'default_value' => 'request',
					'layout'        => 'horizontal',
				),

				array(
					'key'               => 'field_bl_price_range',
					'label'             => __( 'Approximate Price Range', 'hal-business-listings' ),
					'name'              => 'price_range',
					'type'              => 'text',
					'instructions'      => __( 'مثال: $500K–$1M', 'hal-business-listings' ),
					'conditional_logic' => array(
						array(
							array(
								'field'    => 'field_bl_price_mode',
								'operator' => '==',
								'value'    => 'range',
							),
						),
					),
				),

				// ملحوظة: حقل معرض الصور اتشال من هنا عمدًا — بيتدار بمنطق
				// منفصل تحت (Native Gallery Meta Box) لأن ACF المجانية
				// اللي عندكم مفيهاش نوع حقل Gallery أصلًا (حصري لـ Pro).

				array(
					'key'           => 'field_bl_status',
					'label'         => __( 'Listing Status', 'hal-business-listings' ),
					'name'          => 'listing_status',
					'type'          => 'select',
					'choices'       => array(
						'available'   => __( 'Available', 'hal-business-listings' ),
						'reserved'    => __( 'Reserved', 'hal-business-listings' ),
						'negotiation' => __( 'Under Negotiation', 'hal-business-listings' ),
						'sold'        => __( 'Sold', 'hal-business-listings' ),
					),
					'default_value' => 'available',
					'instructions'  => __( '⚠️ يتغيّر يدويًا من الفريق فقط بعد التحقق — لا يتغير تلقائيًا عند إرسال أي فورم', 'hal-business-listings' ),
					'required'      => 1,
				),

			),
			'location' => array(
				array(
					array(
						'param'    => 'post_type',
						'operator' => '==',
						'value'    => 'business_listing',
					),
				),
			),
			'position'     => 'acf_after_title',
			'style'        => 'default',
			'label_placement' => 'top',
			'show_in_rest' => false,
		)
	);

	// Card C3 — Section 2 of the approved editor IA: public contact data.
	// Field names ARE the Task 4A approved meta keys (single canonical store,
	// REST-registered by class-hal-bl-editor.php) — never seller data.
	acf_add_local_field_group(
		array(
			'key'      => 'group_business_listing_public_contact',
			'title'    => __( 'Public contact information', 'hal-business-listings' ),
			'fields'   => array(
				array(
					'key'   => 'field_bl_public_phone',
					'label' => __( 'Public phone', 'hal-business-listings' ),
					'name'  => '_hal_bl_public_phone',
					'type'  => 'text',
				),
				array(
					'key'   => 'field_bl_public_email',
					'label' => __( 'Public email', 'hal-business-listings' ),
					'name'  => '_hal_bl_public_email',
					'type'  => 'email',
				),
				array(
					'key'   => 'field_bl_public_website',
					'label' => __( 'Public website', 'hal-business-listings' ),
					'name'  => '_hal_bl_public_website',
					'type'  => 'url',
				),
			),
			'location' => array(
				array(
					array(
						'param'    => 'post_type',
						'operator' => '==',
						'value'    => 'business_listing',
					),
				),
			),
			'position'     => 'acf_after_title',
			'style'        => 'default',
			'label_placement' => 'top',
			'show_in_rest' => false,
		)
	);

}
add_action( 'acf/init', 'hal_bl_register_acf_fields' );

/**
 * Data-contract sanitization (plan §4, public phone): the stored value is a
 * phone-like string — digits with +, spaces, dashes, parentheses and dots —
 * never free text, and never on the confidential seller phone keys.
 */
function hal_bl_sanitize_phone_like( $value ): string {
	$clean = preg_replace( '/[^0-9+()\-\s.]/', '', (string) $value );
	return is_string( $clean ) ? trim( preg_replace( '/\s{2,}/', ' ', $clean ) ) : '';
}

/**
 * ACF canvas save path for the public phone field: the REST contract in
 * class-hal-bl-editor.php applies the same sanitizer to REST writes, so
 * both write paths store a phone-like string for _hal_bl_public_phone.
 */
function hal_bl_sanitize_public_phone_acf( $value, $post_id, $field ) {
	if ( empty( $field['key'] ) || 'field_bl_public_phone' !== $field['key'] ) {
		return $value;
	}

	return hal_bl_sanitize_phone_like( $value );
}
add_filter( 'acf/update_value', 'hal_bl_sanitize_public_phone_acf', 10, 3 );


/**
 * 3) Company Gallery — Card C3: the classic side meta-box presentation is
 * retired. The replacement editor panel (admin-editor.js + editor class)
 * owns selection; storage (`company_gallery`) and its secure save path
 * below remain the single canonical channel, unchanged.
 */
function hal_bl_save_gallery( int $post_id ): void {
	$nonce = isset( $_POST['hal_bl_gallery_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['hal_bl_gallery_nonce'] ) ) : '';

	if ( ! wp_verify_nonce( $nonce, 'hal_bl_save_gallery' ) ) {
		return;
	}

	if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
		return;
	}

	if ( ! current_user_can( 'edit_post', $post_id ) ) {
		return;
	}

	$raw = isset( $_POST['company_gallery_ids'] ) ? sanitize_text_field( wp_unslash( $_POST['company_gallery_ids'] ) ) : '';
	$ids = array_values( array_unique( array_filter( array_map( 'absint', explode( ',', $raw ) ) ) ) );

	// إبقاء أرقام مرفقات صور فعلية فقط، تجنبًا لتخزين قيم عشوائية
	$ids = array_values(
		array_filter(
			$ids,
			function ( $id ) {
				return current_user_can( 'edit_post', $id ) && 'attachment' === get_post_type( $id ) && wp_attachment_is_image( $id );
			}
		)
	);

	if ( ! empty( $ids ) ) {
		update_post_meta( $post_id, 'company_gallery', $ids );
	} else {
		delete_post_meta( $post_id, 'company_gallery' );
	}
}
add_action( 'save_post_business_listing', 'hal_bl_save_gallery' );

/**
 * دالة عرض المعرض في القالب الأمامي:
 * echo hal_bl_get_gallery_html( get_the_ID() );
 */
function hal_bl_get_gallery_html( int $post_id ): string {
	if ( '1' !== get_post_meta( $post_id, 'public_visual_approved', true ) ) {
		return '';
	}

	$ids = get_post_meta( $post_id, 'company_gallery', true );

	if ( empty( $ids ) || ! is_array( $ids ) ) {
		return '';
	}

	$html = '<div class="bl-gallery" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px;">';

	foreach ( $ids as $id ) {
		$html .= wp_get_attachment_image( $id, 'medium', false, array( 'loading' => 'lazy' ) );
	}

	return $html . '</div>';
}

/**
 * Detection only. Identifies listings whose visual associations predate an
 * explicit approval decision; never mutates data.
 */
function hal_bl_visual_policy_needs_review( int $post_id ): bool {
	return 'business_listing' === get_post_type( $post_id )
		&& '1' !== get_post_meta( $post_id, 'public_visual_approved', true )
		&& ( has_post_thumbnail( $post_id ) || get_post_meta( $post_id, 'company_gallery', true ) );
}

/**
 * Removes visual associations from an unapproved listing, keeping a backup meta
 * for restore. Invoked exclusively from the nonce/capability-protected admin
 * action below — never automatically on upgrade or on post save.
 */
function hal_bl_enforce_public_visual_policy( int $post_id ): void {
	if ( 'business_listing' !== get_post_type( $post_id ) ) {
		return;
	}

	if ( '1' === get_post_meta( $post_id, 'public_visual_approved', true ) ) {
		return;
	}

	$backup = array();
	$thumbnail_id = get_post_thumbnail_id( $post_id );
	if ( $thumbnail_id ) {
		$backup['thumbnail_id'] = (int) $thumbnail_id;
	}

	$gallery = get_post_meta( $post_id, 'company_gallery', true );
	if ( ! empty( $gallery ) && is_array( $gallery ) ) {
		$backup['gallery'] = array_map( 'absint', $gallery );
	}

	if ( ! empty( $backup ) ) {
		update_post_meta( $post_id, '_hal_bl_visual_backup', $backup );
	}

	delete_post_thumbnail( $post_id );
	delete_post_meta( $post_id, 'company_gallery' );
}

/**
 * Reviews existing listings in small batches and records those awaiting a
 * visual-policy decision. No deletion happens here; application of the policy
 * is an explicit administrative action.
 */
function hal_bl_review_public_visuals_batch(): bool {
	global $wpdb;

	if ( ! hal_bl_acquire_lock( 'hal_bl_visual_policy_review_lock' ) ) {
		return false;
	}

	$cursor   = absint( get_option( 'hal_bl_visual_policy_review_cursor', 0 ) );
	$batch    = 50;
	$listings = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->posts} WHERE post_type = %s AND ID > %d ORDER BY ID ASC LIMIT %d", 'business_listing', $cursor, $batch ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

	$pending = get_option( 'hal_bl_visual_policy_pending', array() );
	$pending = is_array( $pending ) ? array_map( 'absint', $pending ) : array();

	foreach ( $listings as $listing_id ) {
		if ( hal_bl_visual_policy_needs_review( (int) $listing_id ) ) {
			$pending[] = (int) $listing_id;
		}
		$cursor = (int) $listing_id;
		update_option( 'hal_bl_visual_policy_review_cursor', $cursor, false );
	}

	update_option( 'hal_bl_visual_policy_pending', array_values( array_unique( $pending ) ), false );

	delete_option( 'hal_bl_visual_policy_review_lock' );
	if ( count( $listings ) < $batch ) {
		delete_option( 'hal_bl_visual_policy_review_cursor' );
		return true;
	}

	return false;
}

function hal_bl_handle_visual_policy_apply(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to run this action.', 'hal-business-listings' ) );
	}
	check_admin_referer( 'hal_bl_apply_visual_policy' );

	$pending = get_option( 'hal_bl_visual_policy_pending', array() );
	$pending = is_array( $pending ) ? array_map( 'absint', $pending ) : array();

	foreach ( $pending as $post_id ) {
		hal_bl_enforce_public_visual_policy( $post_id );
	}

	delete_option( 'hal_bl_visual_policy_pending' );

	wp_safe_redirect(
		add_query_arg(
			array(
				'post_type'           => 'business_listing',
				'page'                => 'hal-bl-listing-settings',
				'hal_bl_visual_policy' => 'applied',
			),
			admin_url( 'edit.php' )
		)
	);
	exit;
}
add_action( 'admin_post_hal_bl_apply_visual_policy', 'hal_bl_handle_visual_policy_apply' );


/**
 * 4) Confidential seller data — Card C3: the classic side meta-box
 * presentation is retired. The restricted panel in the replacement editor
 * owns display (capability-gated boot data via class-hal-bl-editor.php);
 * storage (the three protected meta keys) and the secure save path below
 * remain the single canonical channel, unchanged.
 */

function hal_bl_save_sensitive_seller_data( int $post_id ): void {
	$nonce = isset( $_POST['hal_bl_sensitive_seller_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['hal_bl_sensitive_seller_nonce'] ) ) : '';
	if ( ! wp_verify_nonce( $nonce, 'hal_bl_save_sensitive_seller_data' ) || ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) ) {
		return;
	}

	if ( ! current_user_can( 'edit_post', $post_id ) || ! current_user_can( hal_bl_seller_field_capability() ) ) {
		return;
	}

	$fields = array(
		'_hal_bl_seller_contact_name'  => isset( $_POST['hal_bl_seller_contact_name'] ) ? sanitize_text_field( wp_unslash( $_POST['hal_bl_seller_contact_name'] ) ) : '',
		'_hal_bl_seller_contact_phone' => isset( $_POST['hal_bl_seller_contact_phone'] ) ? sanitize_text_field( wp_unslash( $_POST['hal_bl_seller_contact_phone'] ) ) : '',
		'_hal_bl_seller_contact_email' => isset( $_POST['hal_bl_seller_contact_email'] ) ? sanitize_email( wp_unslash( $_POST['hal_bl_seller_contact_email'] ) ) : '',
	);

	foreach ( $fields as $meta_key => $value ) {
		if ( '' === $value ) {
			delete_post_meta( $post_id, $meta_key );
		} else {
			update_post_meta( $post_id, $meta_key, $value );
		}
	}
}
add_action( 'save_post_business_listing', 'hal_bl_save_sensitive_seller_data' );

function hal_bl_prevent_sensitive_acf_shortcode_access( bool $prevent, array $atts, $post_id, string $post_type, string $field_type, array $field ): bool {
	if ( 'post' === $post_type && 'business_listing' === get_post_type( (int) $post_id ) && in_array( $field['name'] ?? '', array( 'seller_contact_name', 'seller_contact_phone', 'seller_contact_email' ), true ) ) {
		return true;
	}

	return $prevent;
}
add_filter( 'acf/shortcode/prevent_access', 'hal_bl_prevent_sensitive_acf_shortcode_access', 10, 6 );

function hal_bl_filter_rest_fields( $fields, array $resource, string $http_method ) {
	if ( ! is_array( $fields ) || 'post' !== ( $resource['type'] ?? '' ) || 'business_listing' !== ( $resource['sub_type'] ?? '' ) ) {
		return $fields;
	}

	foreach ( $fields as $key => $field ) {
		if ( in_array( $field['name'] ?? '', array( 'seller_contact_name', 'seller_contact_phone', 'seller_contact_email' ), true ) ) {
			unset( $fields[ $key ] );
		}
	}

	return $fields;
}
add_filter( 'acf/rest/get_fields', 'hal_bl_filter_rest_fields', 10, 3 );

/**
 * 6) رابط سريع لقائمة الإعلانات من صفحة الإضافات — تكامل بسيط
 * يسهّل وصول الفريق لشاشة الإدارة دون البحث في القائمة الجانبية.
 */
function hal_bl_add_action_links( array $links ): array {
	$listings_url = admin_url( 'edit.php?post_type=business_listing' );
	$links[]      = '<a href="' . esc_url( $listings_url ) . '">' . esc_html__( 'View Listings', 'hal-business-listings' ) . '</a>';
	return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( HAL_BL_FILE ), 'hal_bl_add_action_links' );
