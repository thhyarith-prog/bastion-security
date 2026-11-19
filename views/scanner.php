<?php
/**
 * Scanner screen.
 *
 * @package Bastion_Security
 */

defined( 'ABSPATH' ) || exit;

$state      = Bastion_Scanner::state();
$running    = Bastion_Scanner::is_running();
$issues     = Bastion_Scanner::issues( 'open' );
$ignored    = Bastion_Scanner::issues( 'ignored' );
$quarantine = Bastion_Scanner::quarantine_list();
$last       = (int) get_option( 'bastion_last_scan_completed' );
$type_names = array(
	'malware'          => __( 'Malware', 'bastion-security' ),
	'core_modified'    => __( 'Core file changed', 'bastion-security' ),
	'core_unknown'     => __( 'Unknown core file', 'bastion-security' ),
	'core_missing'     => __( 'Core file missing', 'bastion-security' ),
	'plugin_modified'  => __( 'Plugin file changed', 'bastion-security' ),
	'plugin_unknown'   => __( 'Unknown plugin file', 'bastion-security' ),
	'php_in_uploads'   => __( 'PHP in uploads', 'bastion-security' ),
	'vuln'             => __( 'Vulnerability', 'bastion-security' ),
	'plugin_closed'    => __( 'Closed plugin', 'bastion-security' ),
	'plugin_abandoned' => __( 'Abandoned plugin', 'bastion-security' ),
	'db_injection'     => __( 'Database', 'bastion-security' ),
	'config'           => __( 'Configuration', 'bastion-security' ),
);

$render_issue = function ( $i, $is_ignored ) use ( $type_names ) {
	$d        = $i->details;
	$is_file  = '' !== $i->file && ( false === strpos( $i->file, ':' ) || preg_match( '~^[a-z]:/~i', $i->file ) );
	?>
	<li class="bastion-issue" data-id="<?php echo (int) $i->id; ?>">
		<div class="bastion-issue__head">
			<?php echo Bastion_Admin::severity_badge( $i->severity ); // phpcs:ignore ?>
			<span class="bastion-issue__type"><?php echo esc_html( isset( $type_names[ $i->type ] ) ? $type_names[ $i->type ] : $i->type ); ?></span>
			<strong class="bastion-issue__title"><?php echo esc_html( $i->title ); ?></strong>
		</div>
		<?php if ( $is_file ) : ?>
			<div class="bastion-issue__file code"><?php echo esc_html( $i->file ); ?><?php echo ! empty( $d['line'] ) ? ':' . (int) $d['line'] : ''; ?></div>
		<?php endif; ?>
		<?php if ( ! empty( $d['snippet'] ) ) : ?>
			<pre class="bastion-snippet"><?php echo esc_html( $d['snippet'] ); ?></pre>
		<?php endif; ?>
		<?php if ( ! empty( $d['help'] ) ) : ?>
			<p class="bastion-issue__help"><?php echo esc_html( $d['help'] ); ?></p>
		<?php endif; ?>
		<?php if ( ! empty( $d['reason'] ) ) : ?>
			<p class="bastion-issue__help"><?php echo esc_html( sprintf( __( 'Reason given: %s', 'bastion-security' ), $d['reason'] ) ); ?></p>
		<?php endif; ?>
		<?php if ( ! empty( $d['links'] ) ) : ?>
			<p class="bastion-issue__links">
				<?php foreach ( $d['links'] as $l ) : ?>
					<a href="<?php echo esc_url( $l['url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $l['name'] ); ?></a>
				<?php endforeach; ?>
			</p>
		<?php endif; ?>
		<div class="bastion-issue__actions">
			<?php if ( $is_file && ! in_array( $i->type, array( 'core_missing' ), true ) ) : ?>
				<button type="button" class="button button-small" data-issue="view"><?php esc_html_e( 'View file', 'bastion-security' ); ?></button>
			<?php endif; ?>
			<?php if ( ! empty( $d['repairable'] ) ) : ?>
				<button type="button" class="button button-small button-primary" data-issue="repair"><?php esc_html_e( 'Restore original', 'bastion-security' ); ?></button>
			<?php endif; ?>
			<?php if ( $is_file && in_array( $i->type, array( 'malware', 'core_unknown', 'plugin_unknown', 'php_in_uploads' ), true ) ) : ?>
				<button type="button" class="button button-small" data-issue="quarantine"><?php esc_html_e( 'Quarantine', 'bastion-security' ); ?></button>
			<?php endif; ?>
			<?php if ( 'vuln' === $i->type || 'plugin_closed' === $i->type || 'plugin_abandoned' === $i->type ) : ?>
				<a class="button button-small" href="<?php echo esc_url( admin_url( 'core' === ( isset( $d['kind'] ) ? $d['kind'] : '' ) ? 'update-core.php' : ( 0 === strpos( $i->file, 'theme:' ) ? 'themes.php' : 'plugins.php' ) ) ); ?>"><?php esc_html_e( 'Manage', 'bastion-security' ); ?></a>
			<?php endif; ?>
			<?php if ( 'db_injection' === $i->type && ! empty( $d['post_id'] ) ) : ?>
				<a class="button button-small" href="<?php echo esc_url( get_edit_post_link( (int) $d['post_id'] ) ); ?>"><?php esc_html_e( 'Edit content', 'bastion-security' ); ?></a>
			<?php endif; ?>
			<?php if ( 'config' === $i->type && ! empty( $d['fix'] ) && 0 === strpos( $d['fix'], 'http' ) ) : ?>
				<a class="button button-small" href="<?php echo esc_url( $d['fix'] ); ?>"><?php esc_html_e( 'Fix', 'bastion-security' ); ?></a>
			<?php endif; ?>
			<?php if ( $is_ignored ) : ?>
				<button type="button" class="button button-small button-link" data-issue="unignore"><?php esc_html_e( 'Stop ignoring', 'bastion-security' ); ?></button>
			<?php else : ?>
				<button type="button" class="button button-small button-link" data-issue="ignore"><?php esc_html_e( 'Ignore', 'bastion-security' ); ?></button>
			<?php endif; ?>
			<span class="bastion-issue__msg" aria-live="polite"></span>
		</div>
	</li>
	<?php
};
?>
<section class="bastion-card bastion-scan" data-running="<?php echo $running ? '1' : '0'; ?>">
	<div class="bastion-scan__head">
		<div>
			<h2><?php esc_html_e( 'Security scan', 'bastion-security' ); ?></h2>
			<p class="bastion-muted bastion-scan__last">
				<?php
				if ( $last ) {
					echo esc_html( sprintf( __( 'Last completed %1$s ago (%2$s).', 'bastion-security' ), human_time_diff( $last ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last ) ) );
				} else {
					esc_html_e( 'No scan has run yet. The first scan takes a few minutes.', 'bastion-security' );
				}
				?>
			</p>
		</div>
		<div>
			<button type="button" class="button button-primary button-hero bastion-scan__start" <?php echo $running ? 'hidden' : ''; ?>><?php esc_html_e( 'Start scan', 'bastion-security' ); ?></button>
			<button type="button" class="button bastion-scan__stop" <?php echo $running ? '' : 'hidden'; ?>><?php esc_html_e( 'Stop', 'bastion-security' ); ?></button>
		</div>
	</div>
	<div class="bastion-progress" <?php echo $running ? '' : 'hidden'; ?>>
		<div class="bastion-progress__bar"><span style="width:0%"></span></div>
		<p class="bastion-progress__msg" aria-live="polite"><?php echo esc_html( isset( $state['message'] ) ? $state['message'] : '' ); ?></p>
	</div>
	<?php if ( ! $running && ! empty( $state['status'] ) && 'failed' === $state['status'] ) : ?>
		<p class="bastion-note bastion-note--bad"><?php echo esc_html( $state['message'] ); ?></p>
	<?php endif; ?>
	<p class="bastion-muted"><?php esc_html_e( 'Checks every WordPress core and WordPress.org plugin file against the official checksums, scans everything else for malware, looks up known vulnerabilities in your installed versions, checks posts and options for injected scripts, and reviews your configuration.', 'bastion-security' ); ?></p>
</section>

<section class="bastion-card">
	<h2><?php esc_html_e( 'Issues', 'bastion-security' ); ?> <span class="bastion-count"><?php echo count( $issues ); ?></span></h2>
	<?php if ( ! $issues ) : ?>
		<p class="bastion-empty"><?php echo $last ? esc_html__( 'No open issues. Your site looks clean.', 'bastion-security' ) : esc_html__( 'Run a scan to see results.', 'bastion-security' ); ?></p>
	<?php else : ?>
		<ul class="bastion-issues">
			<?php
			foreach ( $issues as $i ) {
				$render_issue( $i, false );
			}
			?>
		</ul>
	<?php endif; ?>
</section>

<?php if ( $ignored ) : ?>
	<details class="bastion-card bastion-details">
		<summary><h2><?php esc_html_e( 'Ignored', 'bastion-security' ); ?> <span class="bastion-count"><?php echo count( $ignored ); ?></span></h2></summary>
		<ul class="bastion-issues">
			<?php
			foreach ( $ignored as $i ) {
				$render_issue( $i, true );
			}
			?>
		</ul>
	</details>
<?php endif; ?>

<?php if ( $quarantine ) : ?>
	<section class="bastion-card">
		<h2><?php esc_html_e( 'Quarantine', 'bastion-security' ); ?> <span class="bastion-count"><?php echo count( $quarantine ); ?></span></h2>
		<p class="bastion-muted"><?php esc_html_e( 'Quarantined files are moved to a protected folder where they cannot run. Restore one if something stopped working.', 'bastion-security' ); ?></p>
		<table class="bastion-table">
			<thead><tr><th><?php esc_html_e( 'File', 'bastion-security' ); ?></th><th><?php esc_html_e( 'Reason', 'bastion-security' ); ?></th><th><?php esc_html_e( 'When', 'bastion-security' ); ?></th><th></th></tr></thead>
			<tbody>
			<?php foreach ( $quarantine as $name => $q ) : ?>
				<tr data-q="<?php echo esc_attr( $name ); ?>">
					<td class="code"><?php echo esc_html( $q['file'] ); ?></td>
					<td><?php echo esc_html( $q['reason'] ); ?></td>
					<td><?php echo esc_html( sprintf( __( '%s ago', 'bastion-security' ), human_time_diff( $q['time'] ) ) ); ?></td>
					<td class="actions">
						<button type="button" class="button button-small" data-quarantine="restore"><?php esc_html_e( 'Restore', 'bastion-security' ); ?></button>
						<button type="button" class="button button-small button-link-delete" data-quarantine="delete"><?php esc_html_e( 'Delete', 'bastion-security' ); ?></button>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</section>
<?php endif; ?>

<section class="bastion-card">
	<h2><?php esc_html_e( 'Scan settings', 'bastion-security' ); ?></h2>
	<?php Bastion_Admin::form_open( 'scanner' ); ?>
	<div class="bastion-fields">
		<?php
		foreach ( array( 'scan_schedule', 'scan_signatures', 'scan_plugin_integrity', 'scan_vulnerabilities', 'scan_abandoned', 'scan_database', 'scan_max_file_mb', 'scan_exclude' ) as $k ) {
			Bastion_Admin::field( $k );
		}
		?>
	</div>
	<?php Bastion_Admin::form_close(); ?>
</section>

<dialog class="bastion-dialog" id="bastion-file-dialog" aria-labelledby="bastion-dialog-title">
	<form method="dialog" class="bastion-dialog__head"><strong class="bastion-dialog__title" id="bastion-dialog-title"></strong><button class="button-link" aria-label="<?php esc_attr_e( 'Close', 'bastion-security' ); ?>">✕</button></form>
	<p class="bastion-dialog__meta bastion-muted"></p>
	<div class="bastion-code" tabindex="0"></div>
</dialog>
