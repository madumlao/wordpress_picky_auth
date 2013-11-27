<?php
class PickyAuthOptionsPage {
	function __construct($options) {
		$this->options = $options;
		$this->option_group = 'picky_auth';
		$this->menu_title = 'Picky Auth';
		$this->page_title = 'Picky Auth Options';
		$this->slug = 'picky_auth';
		
		if (is_admin()) {
			add_action('admin_menu', array($this, 'add_menu_item'));
			add_action('admin_init', array($this, 'register_settings'));
		}
	}
	
	function add_menu_item() {
		add_options_page(
			$this->page_title,
			$this->menu_title,
			'manage_options',
			$this->slug,
			array($this, 'display_options_page')
		);
	}
	
	function display_options_page() {
		if (!current_user_can('manage_options')) {
			wp_die(__('You do not have sufficient permissions to access this page.'));
		}
?><div class="wrap">
	<?php screen_icon(); ?>
	<h2><?php echo $this->page_title; ?></h2>
	<form action="options.php" method="post">
	<h3>x509 attributes</h3>
	<p>Attribute fields refer to the x509 attribute (as parsed by PHP) used to match or create users. Separate subattributes using commas. Common attributes:</p>
	<ul>
		<li>DN: <code>name</code></li>
		<li>Common name: <code>subject,CN</code></li>
		<li>Email: <code>extensions,subjectAltName</code></li>
	</ul>
	<h3>Regexes and matches</h3>
	<p>The value to be created or matched in the database is determined by applying a regular expression against the attribute. Common regexes and matches:</p>
	<ul>
		<li>Get the whole attribute:<br />
			Regex: <code>/(.*)/</code>| Match:<code>(.*)</code></li>
		<li>Get the email:<br />
			Regex: <code>/(^email:(.*))/</code>| Match:<code>$2</code></li>
	</ul>
	<hr />
	<?php settings_fields($this->option_group); ?>
	<?php do_settings_sections($this->slug); ?>
	<?php submit_button(); ?>
	</form>
</div><?php
	}
	
	function register_settings() {
		register_setting($this->option_group, 'picky_auth_type');
		register_setting($this->option_group, 'picky_auth_cert_variable');
		register_setting($this->option_group, 'picky_auth_attribute');
		register_setting($this->option_group, 'picky_auth_regex');
		register_setting($this->option_group, 'picky_auth_match');
		register_setting($this->option_group, 'picky_auth_autocreate');
		register_setting($this->option_group, 'picky_auth_autocreate_login_attribute');
		register_setting($this->option_group, 'picky_auth_autocreate_login_regex');
		register_setting($this->option_group, 'picky_auth_autocreate_login_match');
		register_setting($this->option_group, 'picky_auth_autocreate_email_attribute');
		register_setting($this->option_group, 'picky_auth_autocreate_email_regex');
		register_setting($this->option_group, 'picky_auth_autocreate_email_match');
		
		$section = 'picky_auth_options_server';
		add_settings_section(
			$section,
			'Server settings',
			array($this, 'display_section_server'),
			$this->slug
		);
		add_settings_field(
			'picky_auth_cert_variable',
			'Server certificate variable',
			array($this, 'display_field_cert_variable'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_cert')
		);
		
		$section = 'picky_auth_options_cert';
		add_settings_section(
			$section,
			'Certificate settings',
			array($this, 'display_section_cert'),
			$this->slug
		);
		add_settings_field(
			'picky_auth_type',
			'Match users by',
			array($this, 'display_field_type'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_type')
		);
		add_settings_field(
			'picky_auth_attribute',
			'Certificate attribute to search',
			array($this, 'display_field_attribute'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_attribute')
		);
		add_settings_field(
			'picky_auth_regex',
			'Regex to use on client certificate attribute',
			array($this, 'display_field_regex'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_regex')
		);
		add_settings_field(
			'picky_auth_match',
			'Part of regex to match',
			array($this, 'display_field_match'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_match')
		);
		
		$section = 'picky_auth_options_autocreate';
		add_settings_section(
			$section,
			'Autocreate settings',
			array($this, 'display_section_autocreate'),
			$this->slug
		);
		add_settings_field(
			'picky_auth_autocreate',
			'Automatically create users?',
			array($this, 'display_field_autocreate'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_autocreate')
		);
		add_settings_field(
			'picky_auth_autocreate_login_attribute',
			'Certificate attribute to use onlogin',
			array($this, 'display_field_autocreate_login_attribute'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_autocreate_login_attribute')
		);
		add_settings_field(
			'picky_auth_autocreate_login_regex',
			'Login regex',
			array($this, 'display_field_autocreate_login_regex'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_autocreate_login_regex')
		);
		add_settings_field(
			'picky_auth_autocreate_login_match',
			'Login match',
			array($this, 'display_field_autocreate_login_match'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_autocreate_login_match')
		);
		add_settings_field(
			'picky_auth_autocreate_email_attribute',
			'Certificate attribute to use on email',
			array($this, 'display_field_autocreate_email_attribute'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_autocreate_email_attribute')
		);
		add_settings_field(
			'picky_auth_autocreate_email_regex',
			'Email regex',
			array($this, 'display_field_autocreate_email_regex'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_autocreate_email_regex')
		);
		add_settings_field(
			'picky_auth_autocreate_email_match',
			'Email match',
			array($this, 'display_field_autocreate_email_match'),
			$this->slug,
			$section,
			array('label_for' => 'picky_auth_autocreate_email_match')
		);
	}
	
	function display_section_server() { ?>
<p>Options affected by your web / application server configuration.</p>
<?	}
	
	function display_section_cert() { ?>
<p>Options that affect how users are mapped to certificates.</p>
<?	}
	
	function display_section_autocreate() { ?>
<p>Options that affect user autocreation.</p>
<?	}
	
	function display_field_cert_variable() {
		$cert_variable = $this->options['picky_auth_cert_variable'];
		$this->display_input_text_field('cert_variable', $cert_variable);
?>
Variable passed by the webserver to PHP holding the client certificate. Default values used by common webservers:
<ul>
	<li>apache, lighthttpd: <code>SSL_CLIENT_CERT</code></li>
	<li>nginx: <code>SSL_CLIENT_RAW_CERT</code></li>
</ul>
<?	}
	
	function display_field_type() {
		$type = $this->options['picky_auth_type'];
		$choices = array(
			'id',
			'login',
			'email',
			'slug',
		);
		$this->display_input_select_field('type', $type, $choices);
?>
Database field to match users against.
<?
	}
	
	function display_field_attribute() {
		$attribute = $this->options['picky_auth_attribute'];
		$this->display_input_text_field('attribute', $attribute);
	}
	
	function display_field_regex() {
		$regex = $this->options['picky_auth_regex'];
		$this->display_input_text_field('regex', $regex);
	}
	
	function display_field_match() {
		$match = $this->options['picky_auth_match'];
		$this->display_input_text_field('match', $match);
	}
	
	function display_field_autocreate() {
		$autocreate = $this->options['picky_auth_autocreate'];
		$this->display_input_checkbox_field('autocreate', $autocreate);
	}
	
	function display_field_autocreate_login_attribute() {
		$attribute = $this->options['picky_auth_autocreate_login_attribute'];
		$this->display_input_text_field('autocreate_login_attribute', $attribute);
	}
	
	function display_field_autocreate_login_regex() {
		$regex = $this->options['picky_auth_autocreate_login_regex'];
		$this->display_input_text_field('autocreate_login_regex', $regex);
	}
	
	function display_field_autocreate_login_match() {
		$match = $this->options['picky_auth_autocreate_login_match'];
		$this->display_input_text_field('autocreate_login_match', $match);
	}
	
	function display_field_autocreate_email_attribute() {
		$attribute = $this->options['picky_auth_autocreate_email_attribute'];
		$this->display_input_text_field('autocreate_email_attribute', $attribute);
	}
	
	function display_field_autocreate_email_regex() {
		$regex = $this->options['picky_auth_autocreate_email_regex'];
		$this->display_input_text_field('autocreate_email_regex', $regex);
	}
	
	function display_field_autocreate_email_match() {
		$match = $this->options['picky_auth_autocreate_email_match'];
		$this->display_input_text_field('autocreate_email_match', $match);
	}
	
	function display_input_select_field($name, $value, $choices) { ?>
<select name="<?php echo htmlspecialchars($this->option_group); ?>_<?php echo htmlspecialchars($name); ?>" id="picky_auth_<?php echo htmlspecialchars($name); ?>">
<? foreach ($choices AS $id => $choice): ?>
	<option value=<?php
	echo '"';
	if (gettype($id) == 'integer') {
		echo htmlspecialchars($choice);
	} else {
		echo htmlspecialchars($id);
	}
	echo '"';
	if ($choice === $value) {
		echo ' selected="selected"';
	} ?>><?php echo $choice ?></option>
<? endforeach; ?>
</select><br />
<?	}
	
	function display_input_text_field($name, $value, $size = 75) { ?>
<input type="text" name="<?php echo htmlspecialchars($this->option_group); ?>_<?php echo htmlspecialchars($name); ?>" id="picky_auth_<?php echo htmlspecialchars($name); ?>" value="<?php echo htmlspecialchars($value); ?>" size="<?php echo htmlspecialchars($size); ?>" /><br />
<?	}
	
	function display_input_checkbox_field($name, $value) { ?>
<input type="hidden" name="<?php echo htmlspecialchars($this->option_group);?>_<?php echo htmlspecialchars($name); ?>" id="picky_auth_<?php echo htmlspecialchars($name); ?>" value="0" />
<input type="checkbox" name="<?php echo htmlspecialchars($this->option_group); ?>_<?php echo htmlspecialchars($name); ?>" id="picky_auth_<?php echo htmlspecialchars($name); ?>" value="1"<?php
	if ($value) echo ' checked="checked"'; ?> /><br />
<?	}
}