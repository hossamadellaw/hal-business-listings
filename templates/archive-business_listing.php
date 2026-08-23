<?php
defined( 'ABSPATH' ) || exit;

get_header();
?>
<main id="primary" class="site-main hal-bl-archive" dir="auto">
	<header class="page-header"><h1 class="page-title"><?php post_type_archive_title(); ?></h1></header>
	<?php if ( have_posts() ) : ?><div class="hal-bl-listing-grid"><?php while ( have_posts() ) : the_post(); $fields = HAL_BL_Display::public_fields( get_the_ID() ); ?>
		<article <?php post_class( 'hal-bl-listing-card' ); ?>>
			<a class="hal-bl-card-visual" href="<?php the_permalink(); ?>"><?php echo wp_kses_post( HAL_BL_Display::render_visual( get_the_ID(), 'hal-bl-listing-card' ) ); ?></a>
			<h2 class="entry-title"><a href="<?php the_permalink(); ?>"><?php the_title(); ?></a></h2>
			<?php echo wp_kses_post( HAL_BL_Display::render_status( $fields['status'] ?? '' ) ); ?>
			<?php echo wp_kses_post( HAL_BL_Display::render_listing_details( array_intersect_key( $fields, array_flip( array( 'reference', 'country', 'city' ) ) ) ) ); ?>
		</article>
	<?php endwhile; ?></div><?php the_posts_pagination(); ?><?php else : ?><p><?php esc_html_e( 'No listings found.', 'hal-business-listings' ); ?></p><?php endif; ?>
</main>
<?php get_footer();
