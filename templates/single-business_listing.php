<?php
defined( 'ABSPATH' ) || exit;

get_header();
while ( have_posts() ) :
	the_post();
	$fields = HAL_BL_Display::public_fields( get_the_ID() );
	?>
	<main id="primary" class="site-main hal-bl-single" dir="auto">
		<article <?php post_class(); ?>>
			<header class="entry-header"><h1 class="entry-title"><?php the_title(); ?></h1></header>
			<div class="hal-bl-visual"><?php echo wp_kses_post( HAL_BL_Display::render_visual( get_the_ID() ) ); ?></div>
			<?php echo wp_kses_post( HAL_BL_Display::render_status( $fields['status'] ?? '' ) ); ?>
			<?php echo wp_kses_post( HAL_BL_Display::render_listing_details( $fields ) ); ?>
			<?php echo wp_kses_post( $fields['gallery'] ?? '' ); ?>
			<div class="entry-content"><?php the_content(); ?></div>
			<div class="hal-bl-cta-wrap"><?php echo wp_kses_post( HAL_BL_Display::render_listing_cta( get_the_ID() ) ); ?></div>
		</article>
	</main>
	<?php
endwhile;
get_footer();
