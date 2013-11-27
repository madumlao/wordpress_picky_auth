<?php
/**
 * Plugin Name: Picky Auth
 * Plugin URI: http://github.com/madumlao/wordpress_picky_auth
 * Description: a plugin for authenticating wordpress users using x509 client certificates
 * Version: 0.9
 * Author: madumlao
 * Author URI: http://madumlao.is-a-geek.org
 * License: GPLv2
 */

/* Copyright 2013 madumlao (email: madumlao@gmail.com)
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2, as
   published by the Free Software Foundation.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA   02110-1301 USA
 */

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'picky-auth-options-page.php');

class PickyAuthPlugin {
	function __construct() {
		add_option('picky_auth_type', 'email');
		add_option('picky_auth_cert_variable', 'SSL_CLIENT_CERT');
		add_option('picky_auth_attribute', 'extensions,subjectAltName');
		add_option('picky_auth_regex', '/^(email:(.*))/');
		add_option('picky_auth_autocreate', '1');
		add_option('picky_auth_autocreate_login_attribute', 'subject,CN');
		add_option('picky_auth_autocreate_login_regex', '/(.*)/');
		add_option('picky_auth_autocreate_login_match', '$1');
		add_option('picky_auth_autocreate_email_attribute', 'extensions,subjectAltName');
		add_option('picky_auth_autocreate_email_regex', '/(^email:(.*))/');
		add_option('picky_auth_autocreate_email_match', '$2');
		add_option('picky_auth_match', '$2');
		
		$this->options = wp_load_alloptions();
		
		if (is_admin()) {
			$options_page = new PickyAuthOptionsPage($this->options);
		}
		
		add_action('login_head', array($this, 'add_login_css'));
		add_action('login_footer', array($this, 'add_login_link'));
		add_action('wp_logout', array($this, 'logout'));
		add_filter('login_url', array($this, 'bypass_reauth'));
		add_filter('authenticate', array($this, 'authenticate'), 10, 3);
	}
	
	function authenticate($user, $username, $password) {
		// check if the user exists
		$attr = $this->get_attr_from_cert(
			$this->get_cert(),
			$this->options['picky_auth_attribute'],
			$this->options['picky_auth_regex'],
			$this->options['picky_auth_match']
		);
		$auth_type = $this->options['picky_auth_type'];
		$user = get_user_by($auth_type, $attr);
		
		if (!$user) {
			// attempt to create a new user
			if ($this->options['picky_auth_autocreate']) {
				$user = $this->create_user();
			}
		}
		
		if (!$user) {
			return new WP_error('authentication_failed', '<strong>ERROR</strong>: Authentication failed.');
		}
		
		return $user;
	}
	
	function create_user() {
		$cert = $this->get_cert();
		$password = wp_generate_password();
		
		// get the login
		$username = $this->get_attr_from_cert(
			$cert,
			$this->options['picky_auth_autocreate_login_attribute'],
			$this->options['picky_auth_autocreate_login_regex'],
			$this->options['picky_auth_autocreate_login_match']
		);
		
		// get the email
		$email = $this->get_attr_from_cert(
			$cert,
			$this->options['picky_auth_autocreate_email_attribute'],
			$this->options['picky_auth_autocreate_email_regex'],
			$this->options['picky_auth_autocreate_email_match']
		);
		
		$user_id = wp_create_user($username, $password, $email);
		return get_user_by('id', $user_id);
	}
	
	/**
	 * returns the client certificate from the configured server variable
	 */
	function get_cert() {
		return $_SERVER[$this->options['picky_auth_cert_variable']];
	}
	
	/**
	 * returns an attribute from a cert
	 *
	 * @param string    $cert string contents of x509 certificate
	 * @param string    $attr list of names to be traversed in x509 certdata
	 * @param string    $regex used to match attribute
	 * @param string    $match value to extract rom regex
	 */
	function get_attr_from_cert($cert, $attr, $regex = '/(.*)/', $match = '$1') {
		$attr = preg_replace('/\s+,|,\s+/', ',', $attr);
		$attr = preg_replace('/\s+$/', '', $attr);
		$attr = explode(',', $attr);
		
		$certdata = openssl_x509_parse($cert);
		if ($certdata) {
			$data = $certdata;
			for ($n=0; $n < count($attr); $data = $data[$attr[$n++]]);
			return preg_replace($regex, $match, $data);
		}
	}
	
	/**
	 * add css to style the login link
	 */
	function add_login_css() { ?>
<style type="text/css">
	#picky-auth-authentication-link {
		width: 100%;
		height: 4em;
		text-align: center;
		margin-top: 2em;
	}
	#picky-auth-authentication-link a {
		margin: 0 auto;
		float: none;
	}
</style>
<?	}
	
	/**
	 * add a link to the login form to initiate external authentication
	 */
	function add_login_link() { ?>
<p id="picky-auth-authentication-link">
	<a class="button-primary" href="<?php echo $this->secure_url(); ?>">
		Login with certificate
	</a>
</p>
<?	}
	
	/**
	 * Generates the login url and forces it to be https
	 */
	function secure_url($url = '') {
		if (!$url) {
			$url = wp_login_url();
		}
		return 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
	}
	
	/**
	 * Returns whether we're on https or not
	 */
	function is_https() {
		$https = !empty($_SERVER['HTTPS']) ? $_SERVER['HTTPS'] : false;
		$forward_proto = !empty($_SERVER['HTTP_X_FORWARDED_PROTO']) ? $_SERVER['HTTP_X_FORWARDED_PROTO'] : false;
		$forward_ssl = !empty($_SERVER['HTTP_X_FORWARDED_SSL']) ? $_SERVER['HTTP_X_FORWARDED_SSL'] : false;
		return ($https == 'on') || ($forward_proto == 'https') || ($forward_ssl == 'on');
	}
	
	/*
	 * Remove the reauth=1 parameter from the login URL, if applicable. This allows
	 * us to transparently bypass the mucking about with cookies that happens in
	 * wp-login.php immediately after wp_signon when a user e.g. navigates directly
	 * to wp-admin.
	 */
	function bypass_reauth($login_url) {
		$login_url = remove_query_arg('reauth', $login_url);

		return $login_url;
	}
	
	/**
	 * Logout the user by redirecting them to the logout URI.
	 */
	function logout() {
		wp_redirect(home_url());
		exit();
	}
}

$picky_auth_plugin = new PickyAuthPlugin();