/**
 * hal-business-listings v1.4.0 - Card C4 (post-C7 correction)
 * Inspector-only sidebar for the business_listing block editor.
 *
 * After the C7 integration gate returned ownership of the duplicated
 * field panels, this file renders no form fields that duplicate the ACF
 * canvas groups (Basic business information / Public contact
 * information, Card C3) or the native title, excerpt, and publishing
 * controls. It owns only: the read-only listing summary, the native
 * featured-image panel pointer, the gallery modal (wp.media), the
 * restricted fail-closed seller panel, starter patterns (core blocks),
 * and the native preview action. Field validation and required-field
 * enforcement live with the owning canvas interfaces (ACF) and WordPress.
 *
 * Loaded on post.php / post-new.php for the business_listing post type
 * only (enqueued by C1). No build step: window.wp.* globals are provided
 * by WordPress. Everything lives inside one IIFE; nothing is added to
 * window.
 */
(function () {
	'use strict';

	var boot = window.halBlEditor || {};

	function isAvailableDeps() {
		return !!(window.wp && window.wp.element && window.wp.components && window.wp.data && window.wp.editPost && window.wp.i18n && window.wp.plugins);
	}

	if (!isAvailableDeps()) {
		// Silent fail-safe: fall back to the untouched native editor.
		return;
	}

	var createElement = window.wp.element.createElement;
	var Fragment = window.wp.element.Fragment;
	var Button = window.wp.components.Button;
	var PanelBody = window.wp.components.PanelBody;
	var PanelRow = window.wp.components.PanelRow;
	var TextControl = window.wp.components.TextControl;
	var Notice = window.wp.components.Notice;
	var Modal = window.wp.components.Modal;
	var PluginSidebar = window.wp.editPost.PluginSidebar;
	var PluginSidebarMoreMenuItem = window.wp.editPost.PluginSidebarMoreMenuItem;
	var useDispatch = window.wp.data.useDispatch;
	var useSelect = window.wp.data.useSelect;
	var createBlock = window.wp.blocks && window.wp.blocks.createBlock ? window.wp.blocks.createBlock : null;
	var __ = window.wp.i18n.__;
	var registerPlugin = window.wp.plugins.registerPlugin;
	var apiFetch = ( window.wp.apiFetch && typeof window.wp.apiFetch === 'function' ) ? window.wp.apiFetch : null;

	var TEXT_DOMAIN = 'hal-business-listings';

	/**
	 * Normalize boot gallery data into [{id, url}]: accepts galleryItems
	 * [{id, url}] or galleryIds [numbers]; ids without a url render a
	 * textual id placeholder. Local state only; C1/C3 own persistence.
	 */
	function normalizeGallery(bootData) {
		var items = [];
		var i;
		if (bootData && Object.prototype.toString.call(bootData.galleryItems) === '[object Array]') {
			for (i = 0; i < bootData.galleryItems.length; i++) {
				var rawItem = bootData.galleryItems[i];
				if (rawItem && rawItem.id !== undefined && rawItem.id !== null) {
					items.push({ id: rawItem.id, url: rawItem.url || '' });
				}
			}
			return items;
		}
		if (bootData && Object.prototype.toString.call(bootData.galleryIds) === '[object Array]') {
			for (i = 0; i < bootData.galleryIds.length; i++) {
				var rawId = bootData.galleryIds[i];
				if (rawId !== undefined && rawId !== null && rawId !== '') {
					items.push({ id: rawId, url: '' });
				}
			}
		}
		return items;
	}

	function MainComponent() {
		var postType = useSelect(function (select) {
			return select('core/editor').getCurrentPostType();
		}, []);

		// Hard scoping rule: render nothing outside business_listing.
		if (postType !== 'business_listing') {
			return null;
		}

		var editorSelect = useSelect(function (select) {
			var store = select('core/editor');
			var previewLink = '';
			if (typeof store.getEditedPostPreviewLink === 'function') {
				previewLink = store.getEditedPostPreviewLink() || '';
			} else if (typeof store.getPreviewLink === 'function') {
				previewLink = store.getPreviewLink() || '';
			}
			var hasDocumentSidebarOpener = false;
			var editPostSelect = select('core/edit-post');
			if (editPostSelect && typeof editPostSelect.isPluginItemVisible !== 'function') {
				hasDocumentSidebarOpener = true; // store exists; dispatcher guarded at call time
			}
			return {
				title: store.getEditedPostAttribute('title') || '',
				status: store.getEditedPostAttribute('status') || '',
				previewLink: previewLink,
				hasDocumentSidebarOpener: hasDocumentSidebarOpener
			};
		}, []);

		var insertBlocks = useDispatch('core/block-editor').insertBlocks;
		var openGeneralSidebar = useDispatch('core/edit-post').openGeneralSidebar;

		// Local-only state: gallery and seller values. The post store owns
		// every other field; nothing in this file writes to it.
		var state = window.wp.element.useState
			? window.wp.element.useState({
				gallery: normalizeGallery(boot),
				galleryOpen: false,
				sellerName: (boot.sellerValues && boot.sellerValues.name) || '',
				sellerPhone: (boot.sellerValues && boot.sellerValues.phone) || '',
				sellerEmail: (boot.sellerValues && boot.sellerValues.email) || '',
				saveState: 'idle' // idle | busy | saved | error
			})
			: null;
		var setState = state[1];
		var data = state[0];

		function update(patchObj) {
			// Functional form: reads the LATEST state at commit time, so an
			// async save completing after further edits never clobbers those
			// newer edits with a stale snapshot (C4-fix-3 race fix).
			setState(function (prev) {
				var next = {};
				var key;
				for (key in prev) {
					if (Object.prototype.hasOwnProperty.call(prev, key)) {
						next[key] = prev[key];
					}
				}
				for (key in patchObj) {
					if (Object.prototype.hasOwnProperty.call(patchObj, key)) {
						next[key] = patchObj[key];
					}
				}
				return next;
			});
		}

		var canOpenNativeSidebar = !!(openGeneralSidebar && editorSelect.hasDocumentSidebarOpener);

		var sellerAllowed =
			!!(window.halBlEditor && window.halBlEditor.sellerPanelAllowed === true && window.halBlEditor.sellerValues && typeof window.halBlEditor.sellerValues === 'object');

		/* ----------------------------------------------------------------
		 * Persistence wiring (C4-fix-2) — the write channels opened by C1-fix.
		 * wp.apiFetch is read defensively from the global; when the package
		 * is absent the write buttons degrade to a notice instead of failing
		 * silently. Both channels below are the canonical ones: the gallery
		 * and the seller values each use their dedicated nonce-guarded
		 * route (C1-fix-2) — core REST meta is not used because
		 * business_listing does not support custom-fields.
		 * -------------------------------------------------------------- */

		function saveNotice(newSaveState) {
			update({ saveState: newSaveState });
		}

		function saveGallery() {
			if (!apiFetch || !boot.galleryRoute || !boot.restNonce) {
				saveNotice('error');
				return Promise.reject(new Error('unavailable'));
			}
			// business_listing does not support custom-fields, so core REST
			// ignores `meta` payloads for it; the gallery uses the dedicated
			// route guarded server-side by edit_post + nonce (C1-fix-2).
			return apiFetch({
				url: boot.galleryRoute,
				method: 'POST',
				data: {
					ids: data.gallery.map(function (item) { return item.id; })
				}
			}).then(function () {
				saveNotice('saved');
			}).catch(function () {
				saveNotice('error');
			});
		}

		function saveSellerContact() {
			if (!apiFetch || !boot.sellerRoute || !boot.restNonce) {
				saveNotice('error');
				return Promise.reject(new Error('unavailable'));
			}
			// The full REST URL goes through apiFetch's `url` option; apiFetch
			// attaches the standard REST nonce header itself, and boot.restNonce
			// guards against a misconfigured middleware (belt-and-suspenders).
			return apiFetch({
				url: boot.sellerRoute,
				method: 'POST',
				data: {
					name: data.sellerName,
					phone: data.sellerPhone,
					email: data.sellerEmail
				}
			}).then(function () {
				saveNotice('saved');
			}).catch(function () {
				saveNotice('error');
			});
		}

		// Public contact fields are owned by the ACF canvas group (C3); the
		// sidebar renders no duplicate inputs for them.

		var saveStateNotice = null;
		if (data.saveState === 'saved') {
			saveStateNotice = createElement(Notice, {
				status: 'success',
				isDismissible: false,
				children: __('Saved.', TEXT_DOMAIN)
			});
		} else if (data.saveState === 'error') {
			saveStateNotice = createElement(Notice, {
				status: 'error',
				isDismissible: false,
				children: __('Saving failed. Please try again.', TEXT_DOMAIN)
			});
		} else if (data.saveState === 'busy') {
			saveStateNotice = createElement(Notice, {
				status: 'info',
				isDismissible: false,
				children: __('Saving…', TEXT_DOMAIN)
			});
		} else if (data.saveState === 'needs-post') {
			saveStateNotice = createElement(Notice, {
				status: 'warning',
				isDismissible: false,
				children: __('Save the listing draft first, then save the gallery.', TEXT_DOMAIN)
			});
		}

		function insertPattern(headingText, paragraphText) {
			if (!createBlock || !insertBlocks) {
				return;
			}
			var blocks = [
				createBlock('core/heading', { content: headingText }),
				createBlock('core/paragraph', { content: paragraphText })
			];
			insertBlocks(blocks);
		}

		function handlePreview() {
			// WordPress's existing preview action — the exact editor-store
			// action the native Preview button drives (gutenberg wp/6.5
			// post-preview-button index.js:153 → store actions.js:334):
			// __unstableSaveForPreview encapsulates the autosaveable/post-lock
			// guards, the draft-save vs published-autosave branching
			// (savePost/autosave with isPreview — the published content is
			// never written by the preview), and resolves with the refreshed
			// preview link. Rejection follows the native semantics: no
			// preview opens (the store surfaces its own error notices); the
			// degraded fallback below only opens the current link without
			// any write when the action itself is unavailable.
			var dataStore = window.wp.data;
			var actions = dataStore && dataStore.dispatch ? dataStore.dispatch('core/editor') : null;
			var selectors = dataStore && dataStore.select ? dataStore.select('core/editor') : null;

			var openPreviewLink = function () {
				var link = '';
				if (selectors && typeof selectors.getEditedPostPreviewLink === 'function') {
					link = selectors.getEditedPostPreviewLink() || '';
				}
				if (link) {
					window.open(link);
				}
			};

			if (actions && actions.__unstableSaveForPreview && typeof actions.__unstableSaveForPreview === 'function') {
				Promise.resolve(actions.__unstableSaveForPreview()).then(function (link) {
					if (link) {
						window.open(link);
					}
				});
				return;
			}

			// Degraded path (store without the action): open the current
			// link read-only — no save is attempted by this file.
			openPreviewLink();
		}

		/* ----------------------------------------------------------------
		 * Gallery modal helpers (wp.media frame, dedupe by id, ordering via
		 * Move up / Move down buttons; no network beyond the media library
		 * session itself, no persistence — C1/C3 own saving).
		 * -------------------------------------------------------------- */

		var galleryButtonRef = null;

		function storeGalleryButton(node) {
			galleryButtonRef = node;
		}

		function restoreGalleryFocus() {
			if (galleryButtonRef && typeof galleryButtonRef.focus === 'function') {
				galleryButtonRef.focus();
			}
		}

		function moveGalleryItem(index, offset) {
			var items = data.gallery.slice(0);
			var target = index + offset;
			if (target < 0 || target >= items.length) {
				return;
			}
			var moved = items[index];
			items[index] = items[target];
			items[target] = moved;
			update({ gallery: items });
		}

		function openMediaFrame() {
			if (!window.wp || !window.wp.media) {
				return;
			}
			var frame = window.wp.media({ title: __('Add gallery images', TEXT_DOMAIN), multiple: true, library: { type: 'image' } });
			frame.on('select', function () {
				var items = data.gallery.slice(0);
				var selection = frame.state().get('selection');
				selection.each(function (attachment) {
					var id = attachment.id;
					var i;
					for (i = 0; i < items.length; i++) {
						if (String(items[i].id) === String(id)) {
							return;
						}
					}
					var attrs = attachment.attributes || {};
					var sizes = attrs.sizes || {};
					var url = '';
					if (sizes.thumbnail && sizes.thumbnail.url) {
						url = sizes.thumbnail.url;
					} else if (attrs.url) {
						url = attrs.url;
					}
					items.push({ id: id, url: url });
				});
				update({ gallery: items });
			});
			// Focus management: return focus to the activating button when the
			// media frame closes (Escape included) without needing to intercept it.
			frame.on('close', restoreGalleryFocus);
			frame.open();
		}

		function renderGalleryModal() {
			if (!data.galleryOpen) {
				return null;
			}
			var listItems = [];
			var i;
			for (i = 0; i < data.gallery.length; i++) {
				var item = data.gallery[i];
				var display = item.url
					? createElement('img', { src: item.url, alt: '', width: 80, height: 80 })
					: createElement('span', null, __('Image #', TEXT_DOMAIN) + ' ' + item.id);
				listItems.push(
					createElement(
						'li',
						{ key: 'gal-' + item.id + '-' + String(i), className: 'hal-bl-gallery-item' },
						createElement(Fragment, null,
							display,
							createElement(Button, {
								type: 'button',
								isSmall: true,
								isSecondary: true,
								disabled: i === 0,
								onClick: (function (index) {
									return function () { moveGalleryItem(index, -1); };
								})(i),
								children: __('Move up', TEXT_DOMAIN)
							}),
							createElement(Button, {
								type: 'button',
								isSmall: true,
								isSecondary: true,
								disabled: i === data.gallery.length - 1,
								onClick: (function (index) {
									return function () { moveGalleryItem(index, 1); };
								})(i),
								children: __('Move down', TEXT_DOMAIN)
							}),
							createElement(Button, {
								type: 'button',
								isSmall: true,
								isDestructive: true,
								isLink: true,
								onClick: (function (index) {
									return function () {
										var items = data.gallery.slice(0);
										items.splice(index, 1);
										update({ gallery: items });
									};
								})(i),
								children: __('Remove', TEXT_DOMAIN)
							})
						)
					)
				);
			}
			return createElement(
				Modal,
				{
					title: __('Manage gallery', TEXT_DOMAIN),
					// Escape is handled natively by the Modal component.
					onRequestClose: function () {
						update({ galleryOpen: false });
						restoreGalleryFocus();
					}
				},
			createElement(Notice, {
				status: 'info',
				isDismissible: false,
				children: __('Gallery changes are kept in this editor session until you save the gallery.', TEXT_DOMAIN)
			}),
				createElement('ul', { className: 'hal-bl-gallery-list' }, listItems),
				createElement(Fragment, null,
					createElement(Button, {
						type: 'button',
						isPrimary: true,
						disabled: data.saveState === 'busy',
						onClick: function () {
							update({ saveState: 'busy' });
							saveGallery().then(function () {
								restoreGalleryFocus();
							}).catch(function () {
								restoreGalleryFocus();
							});
						},
						children: data.saveState === 'busy' ? __('Saving…', TEXT_DOMAIN) : __('Save gallery', TEXT_DOMAIN)
					}),
					createElement(Button, {
						type: 'button',
						isSecondary: true,
						onClick: openMediaFrame,
						children: __('Add images', TEXT_DOMAIN)
					})
				)
			);
	}

		/* ----------------------------------------------------------------
		 * Patterns panel — Section 3 helper: inserts core blocks into the
		 * native editor; never a parallel content editor.
		 * -------------------------------------------------------------- */

		var patternsPanel = createElement(
			PanelBody,
			{ title: __('Native Gutenberg content', TEXT_DOMAIN), initialOpen: true },
			createElement(PanelRow, null,
				createElement('p', null, __('Use the native editor below. The buttons insert a starter heading and paragraph block; edit them like any other block.', TEXT_DOMAIN))
			),
			createElement(PanelRow, null,
				createElement(Button, {
					type: 'button',
					isSecondary: true,
					onClick: function () { insertPattern(__('About the business', TEXT_DOMAIN), __('Describe the company history, mission, and background.', TEXT_DOMAIN)); },
					children: __('Insert About the business', TEXT_DOMAIN)
				})
			),
			createElement(PanelRow, null,
				createElement(Button, {
					type: 'button',
					isSecondary: true,
					onClick: function () { insertPattern(__('Services', TEXT_DOMAIN), __('List the main services offered by the business.', TEXT_DOMAIN)); },
					children: __('Insert Services', TEXT_DOMAIN)
				})
			),
			createElement(PanelRow, null,
				createElement(Button, {
					type: 'button',
					isSecondary: true,
					onClick: function () { insertPattern(__('Why choose us', TEXT_DOMAIN), __('Explain what makes this business stand out.', TEXT_DOMAIN)); },
					children: __('Insert Why choose us', TEXT_DOMAIN)
				})
			)
		);

		/* ----------------------------------------------------------------
		 * Summary panel — read-only inspector view of store-owned data plus
		 * pointers to the native interfaces that own the real controls.
		 * -------------------------------------------------------------- */

		var summaryPanel = createElement(
			PanelBody,
			{ title: __('Listing summary', TEXT_DOMAIN), initialOpen: true },
			createElement(PanelRow, null,
				createElement('p', null, createElement('strong', null, __('Title', TEXT_DOMAIN) + ': '), ' ', editorSelect.title)
			),
			createElement(PanelRow, null,
				createElement('p', null, createElement('strong', null, __('Status', TEXT_DOMAIN) + ': '), ' ', editorSelect.status)
			),
			createElement(PanelRow, null,
				createElement('p', null, __('Status and visibility settings are managed by the native WordPress panels.', TEXT_DOMAIN))
			),
			canOpenNativeSidebar
				? createElement(Button, {
					type: 'button',
					isSecondary: true,
					onClick: function () { openGeneralSidebar('edit-post/document'); },
					children: __('Open the native featured-image panel', TEXT_DOMAIN)
				})
				: null,
			createElement(PanelRow, null,
				createElement(Notice, {
					status: 'info',
					isDismissible: false,
					children: __('SEO fields are managed by the native Rank Math panel.', TEXT_DOMAIN)
				})
			),
			createElement(PanelRow, null,
				createElement(Notice, {
					status: 'info',
					isDismissible: false,
					children: __('Gallery and seller information are saved through their own secured channels in this sidebar. Publishing and content stay owned by WordPress.', TEXT_DOMAIN)
				})
			),
			saveStateNotice
		);

		/* ----------------------------------------------------------------
		 * Restricted seller panel — fail-closed: rendered only when the
		 * capability-gated boot data explicitly allows it. Local edits
		 * only; no network writes from this file.
		 * -------------------------------------------------------------- */

		var sellerPanel = null;
		if (sellerAllowed) {
			sellerPanel = createElement(
				PanelBody,
				{ title: __('Restricted seller information', TEXT_DOMAIN), initialOpen: false, className: 'hal-bl-seller-panel' },
				createElement(TextControl, {
					label: __('Seller contact name', TEXT_DOMAIN),
					type: 'text',
					value: data.sellerName,
					onChange: function (value) { update({ sellerName: value }); }
				}),
				createElement(TextControl, {
					label: __('Seller contact phone', TEXT_DOMAIN),
					type: 'tel',
					value: data.sellerPhone,
					onChange: function (value) { update({ sellerPhone: value }); }
				}),
				createElement(TextControl, {
					label: __('Seller contact email', TEXT_DOMAIN),
					type: 'email',
					value: data.sellerEmail,
					onChange: function (value) { update({ sellerEmail: value }); }
				}),
				createElement(Button, {
					type: 'button',
					isPrimary: true,
					disabled: data.saveState === 'busy',
					onClick: function () {
						update({ saveState: 'busy' });
						saveSellerContact().catch(function () { /* notice state set inside */ });
					},
					children: data.saveState === 'busy' ? __('Saving…', TEXT_DOMAIN) : __('Save seller information', TEXT_DOMAIN)
				})
			);
		}

		/* ----------------------------------------------------------------
		 * Actions: native preview link and the gallery modal trigger.
		 * Publishing and saving remain owned by WordPress only.
		 * -------------------------------------------------------------- */

		var actionsRow = createElement(
			PanelBody,
			{ title: __('Actions', TEXT_DOMAIN), initialOpen: true },
			createElement(PanelRow, null,
				createElement(Fragment, null,
					editorSelect.previewLink
						? createElement(Button, {
							type: 'button',
							isPrimary: true,
							onClick: handlePreview,
							children: __('Preview', TEXT_DOMAIN)
						})
						: null,
					createElement(Button, {
						type: 'button',
						isSecondary: true,
						ref: storeGalleryButton,
						onClick: function () { update({ galleryOpen: true }); },
						children: __('Manage gallery', TEXT_DOMAIN)
					})
				)
			)
		);

		return createElement(
			Fragment,
			null,
			createElement(
				PluginSidebar,
				{ name: 'hal-business-listings-editor', title: __('Business Listing', TEXT_DOMAIN) },
				patternsPanel,
				summaryPanel,
				sellerPanel,
				actionsRow,
				renderGalleryModal()
			),
			createElement(PluginSidebarMoreMenuItem, {
				name: 'hal-business-listings-editor',
				icon: 'dashicons-building',
				children: __('Business Listing', TEXT_DOMAIN)
			})
		);
	}

	registerPlugin('hal-business-listings-editor', {
		icon: 'dashicons-building',
		render: MainComponent
	});
})();
