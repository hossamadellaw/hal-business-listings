jQuery(function ($) {
	function currentIds() { return $('#hal-bl-gallery-ids').val().split(',').filter(Boolean); }
	function setIds(ids) { $('#hal-bl-gallery-ids').val(ids.join(',')); }
	function syncIds() {
		var ids = [];
		$('#hal-bl-gallery-list li').each(function () { ids.push($(this).data('id').toString()); });
		setIds(ids);
	}

	$('#hal-bl-gallery-list').sortable({ update: syncIds });
	$('#hal-bl-add-images').on('click', function (event) {
		event.preventDefault();
		var frame = wp.media({ title: halBlGallery.title, multiple: true, library: { type: 'image' } });
		frame.on('select', function () {
			var ids = currentIds();
			frame.state().get('selection').each(function (attachment) {
				var id = attachment.id.toString();
				if (ids.indexOf(id) !== -1) { return; }
				ids.push(id);
				var url = attachment.attributes.sizes && attachment.attributes.sizes.thumbnail ? attachment.attributes.sizes.thumbnail.url : attachment.attributes.url;
				var $item = $('<li>', { 'data-id': id }).css({ listStyle: 'none', position: 'relative', cursor: 'move' });
				var $image = $('<img>', { src: url, alt: '' }).css({ width: '80px', height: '80px', objectFit: 'cover' });
				var $remove = $('<button>', { type: 'button', class: 'hal-bl-remove-image button-link', text: '\u00d7' }).css({ position: 'absolute', top: '0', right: '0', background: '#fff' });
				$item.append($image, $remove);
				$('#hal-bl-gallery-list').append($item);
			});
			setIds(ids);
		});
		frame.open();
	});
	$('#hal-bl-gallery-list').on('click', '.hal-bl-remove-image', function () { $(this).closest('li').remove(); syncIds(); });
});
