=== Hossam Adel Law Firm — Business Listings ===
Contributors: hossamadellaw
Tags: custom-post-type, acf, mergers-acquisitions, business-listings, elementor, featured-image, amelia
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.3
Stable tag: 1.3.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Private WordPress plugin for managing public M&A business listings while keeping seller contact data separate from public listing fields.

== Description ==

The plugin registers the `business_listing` custom post type and the `listing_country` taxonomy, provides ACF fields for public listing data, and stores seller contact information in protected post meta with a dedicated capability.

Highlights:

* Uses explicit custom capabilities for listings. Administrators receive them on activation; grant them to any deal-management role deliberately.
* Stores seller contact details outside ACF under protected meta keys and migrates legacy `seller_contact_*` data once on upgrade.
* Excludes confidential fields from the native Custom Fields UI, ACF REST responses, ACF shortcode access, and all plugin shortcodes.
* Places the public ACF listing fields directly below the title and puts the Gallery and Confidential Seller Information panels in the high-priority sidebar for faster entry on new listings.
* Provides a native, sortable image gallery using the WordPress media library and verifies both image type and edit permission for every attachment.
* Registers three Elementor-ready CTA shortcodes: `[hal_bl_consultation_cta]`, `[hal_bl_reserve_cta]`, and `[hal_bl_seller_cta]`.
* Adds the Elementor `HAL Listing Visual` widget for Loop Grid cards. It displays a publicly approved featured image when available, otherwise a sector-specific SVG placeholder, then a generic M&A placeholder.
* Keeps public visuals confidential by default: a featured image is shown only when the editor enables `Public visual approved` for that listing.
* Uses fixed, language-independent industry values with translated editor labels. Existing unmatched text values are retained and safely use the generic placeholder.
* Registers a cropped `hal-bl-listing-card` image size (800x500) and accessible, decorative placeholders without stock images, attachment IDs, or external requests.
* Registers the class-scoped frontend stylesheet for native listing views and lets Elementor load it as a dependency only where `HAL Listing Visual` is used.
* Integrates with Amelia Elite’s documented API only from the server: services, categories, and employees are synchronized into an atomic twelve-hour catalog. The key is never printed or sent to visitors.
* Uses Amelia’s official booking shortcode with optional service, category, and employee filters. No dedicated booking-page URL is required; unavailable booking mappings fall back safely to the Contact page.
* Adds an integration screen with manual catalog refresh. Amelia hooks invalidate the catalog after supported changes, while scheduled synchronization remains a fallback.
* Stores the optional practice-area context as a Page ID rather than a URL. This survives permalink changes and resolves the current language through WPML.
* Does not delete listings, gallery data, countries, or seller information on uninstall.

== Installation ==

1. Install and activate Advanced Custom Fields.
2. Upload and activate this exact 1.3.1 plugin folder or its matching ZIP package. Do not mix files from another release.
3. Go to Business Listings → Integrations.
4. In Amelia, enable the API feature and generate an API key. Amelia documents this feature as Elite-only.
5. Save the key once. Prefer the server constant `HAL_BL_AMELIA_API_KEY` in production; otherwise the key is stored in a non-autoloaded WordPress option and is displayed only as a fixed mask after saving.
6. Use “Refresh Amelia catalog”, then select the optional service, category, and employee filters from the discovered lists. Do not type IDs manually.
7. Go to Business Listings → Listing Settings and select the published Companies practice-area page if a contextual link is needed. Use `[hal_bl_context_link]` in an Elementor Shortcode widget.
8. Grant listing capabilities only to trusted deal-management roles.
9. Confirm the generated archive at `/companies-for-sale/`. Native views use the active theme or site builder; the bundled single/archive templates apply only when the `hal_bl_use_plugin_templates` filter is enabled explicitly.
10. In an Elementor Loop Item for `business_listing`, use the `HAL Listing Visual` widget instead of an Image or Shortcode widget. Select an industry for each listing and enable `Public visual approved` only for images cleared for public disclosure.

== Compatibility ==

* WordPress: 6.5+ (header declares tested up to 7.0).
* PHP: 8.3+ with strict types throughout.
* Advanced Custom Fields: required (`Requires Plugins`); the field group uses ACF Free field types only.
* Elementor: optional; `HAL Listing Visual` and public Dynamic Tags register only while Elementor is active, and the dynamic-tags editing UI requires Elementor Pro.
* WPML: optional; resolves the practice-area context page per language and copies stable values between translations.
* Amelia: optional; Amelia documents its API feature (used here for catalog discovery) as Elite-only.
* WooCommerce: no integration exists in this plugin and none is claimed.

== Amelia API and booking context ==

Amelia’s API key authorizes server-to-server calls. This plugin retrieves paginated services, categories, and employees through WordPress, stores a complete catalog only after a successful fetch, and keeps the last valid catalog on refresh failure. It does not expose the key, create an unauthenticated public API endpoint, or change a listing status automatically.

The visitor CTA renders Amelia’s own booking shortcode with the configured service, category, and employee filters. Seller contact data is never passed to Amelia by this plugin.

== Privacy and security ==

Seller information is private operational data. The plugin limits it at the WordPress application layer, but database and hosting administrators remain trusted operators. Define retention and deletion procedures before collecting live seller data, rotate Amelia API keys before their expiry, and keep WordPress, PHP, ACF, Amelia, Elementor, and WPML updated.

== Frequently Asked Questions ==

= Does this require ACF PRO? =

No. All public fields use ACF Free field types; the gallery uses the native WordPress media library.

= Does this require Amelia Elite? =

Only automatic service discovery through Amelia’s API requires Amelia Elite. Without a valid API configuration, all CTAs retain their safe Contact-page fallback.

= Do visitors need a dedicated booking page once the API key is set? =

No dedicated URL is needed. The API runs server-side only to build the catalog; Amelia’s own shortcode, rendered by the CTA shortcodes, is the visitor-facing scheduling interface. The Contact-page fallback appears only when the plugin’s booking markup itself comes back empty — a missing cached catalog alone does not trigger it while explicit service/category/employee mappings are configured.

= Does this install Elementor or WPML? =

No. Both are optional. When Elementor is active, the plugin registers the `HAL Listing Visual` widget; without Elementor, the rest of the plugin continues to work. WPML resolves the selected context page for the current language and copies the stable industry and visual-approval values between translations.

= How does HAL Listing Visual protect confidential listings? =

The widget shows a featured image only when the listing has one and `Public visual approved` is enabled. Otherwise it shows a decorative sector placeholder. Do not enable approval for a logo, premises, product, or other image that may identify a confidential seller.

= Who can view seller contact details? =

Only users with the `manage_hal_bl_sensitive_data` capability, which is initially granted to Administrators.

== Changelog ==

= 1.3.2 =
* Release-engineering bump to validate the GitHub Releases update cycle end-to-end. No functional changes.

= 1.3.1 =
* Reorganized the plugin into focused Bootstrap, listings, display, and optional Elementor modules with fallback single/archive templates.
* Added public-only Elementor Dynamic Tags and scoped frontend template styles.
* Reworked Amelia catalog discovery for paginated services, categories, and employees with atomic caching, protected refresh, hook invalidation, and scheduled sync.
* Replaced the required booking-page URL with Amelia booking shortcodes and optional service/category/employee mappings.

= 1.3.0 =
* Integrated the actual consultation and buyer-introduction CTA shortcodes into the release.
* Added Amelia Elite API service discovery, twelve-hour caching, manual refresh, service dropdown mapping, status reporting, and minimal non-PII diagnostics.
* Kept API traffic server-side and retained safe contact fallbacks for every unavailable booking dependency.
* Added the WPML-aware practice-area Page selector and `[hal_bl_context_link]` shortcode.
* Loaded the scoped frontend CTA stylesheet on listing views and improved visible keyboard focus and reduced-motion behavior.
* Moved listing fields below the title and moved native listing panels to the high-priority sidebar.
* Removed deployment ambiguity by documenting that the complete 1.3.0 folder or matching package must be installed together.
* Added the Elementor `HAL Listing Visual` widget with secure featured-image approval, stable industry placeholders, a generic fallback, and conditional widget CSS loading.
* Changed the Industry field to fixed internal values with translated labels, and configured WPML to copy its value and the visual-approval flag.
* Updated Amelia service discovery to use `/services?page=1` first, with the existing entities endpoint as a compatibility fallback.

= 1.2.0 =
* Raised the PHP baseline to 8.3.
* Added explicit listing capabilities and protected seller-data storage with a one-time legacy migration.
* Removed the native Custom Fields escape hatch and moved ACF registration to `acf/init`.
* Added REST and ACF shortcode protections for confidential field names.
* Integrated the optional Amelia CTA layer with safe contact fallbacks.
* Corrected WPML gallery metadata and stopped replicating seller PII across translations.

= 1.1.0 =
* Previous release.
