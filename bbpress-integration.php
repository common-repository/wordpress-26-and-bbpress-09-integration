<?php
/*
Plugin Name: WordPress 2.6+ and bbPress 0.9 cookie integration
Plugin URI: http://superann.com/wordpress-26-27-bbpress-09-cookie-integration-plugin/
Description: Enables WordPress 2.6 and up to generate cookies that work with bbPress 0.9 so that single sign-on can be accomplished between the two.
Version: 1.0
Author: Ann Oyama (using WordPress source code)
Author URI: http://superann.com

== Version 1.0 ==
2009.02.25: Copied and pasted from WordPress 2.5.1 pluggable.php source code.

Copyright 2009

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

*/

if ( !function_exists('wp_validate_auth_cookie') ) :
function wp_validate_auth_cookie($cookie = '') {
	if ( empty($cookie) ) {
		if ( empty($_COOKIE[AUTH_COOKIE]) )
			return false;
		$cookie = $_COOKIE[AUTH_COOKIE];
	}

	$cookie_elements = explode('|', $cookie);
	if ( count($cookie_elements) != 3 )
		return false;

	list($username, $expiration, $hmac) = $cookie_elements;

	$expired = $expiration;

	// Allow a grace period for POST and AJAX requests
	if ( defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD'] )
		$expired += 3600;

	// Quick check to see if an honest cookie has expired
	if ( $expired < time() )
		return false;

	$key = wp_hash($username . '|' . $expiration);
	$hash = hash_hmac('md5', $username . '|' . $expiration, $key);

	if ( $hmac != $hash )
		return false;

	$user = get_userdatabylogin($username);
	if ( ! $user )
		return false;

	return $user->ID;
}
endif;

if ( !function_exists('wp_generate_auth_cookie') ) :
function wp_generate_auth_cookie($user_id, $expiration) {
	$user = get_userdata($user_id);

	$key = wp_hash($user->user_login . '|' . $expiration);
	$hash = hash_hmac('md5', $user->user_login . '|' . $expiration, $key);

	$cookie = $user->user_login . '|' . $expiration . '|' . $hash;

	return apply_filters('auth_cookie', $cookie, $user_id, $expiration);
}
endif;

if ( !function_exists('wp_set_auth_cookie') ) :
function wp_set_auth_cookie($user_id, $remember = false) {
	if ( $remember ) {
		$expiration = $expire = time() + 1209600;
	} else {
		$expiration = time() + 172800;
		$expire = 0;
	}

	$cookie = wp_generate_auth_cookie($user_id, $expiration);

	do_action('set_auth_cookie', $cookie, $expire);

	setcookie(AUTH_COOKIE, $cookie, $expire, COOKIEPATH, COOKIE_DOMAIN);
	if ( COOKIEPATH != SITECOOKIEPATH )
		setcookie(AUTH_COOKIE, $cookie, $expire, SITECOOKIEPATH, COOKIE_DOMAIN);
}
endif;

if ( !function_exists('wp_clear_auth_cookie') ) :
function wp_clear_auth_cookie() {
	setcookie(AUTH_COOKIE, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN);
	setcookie(AUTH_COOKIE, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN);

	// Old cookies
	setcookie(USER_COOKIE, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN);
	setcookie(PASS_COOKIE, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN);
	setcookie(USER_COOKIE, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN);
	setcookie(PASS_COOKIE, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN);
}
endif;

if ( !function_exists('auth_redirect') ) :
function auth_redirect() {
	// Checks if a user is logged in, if not redirects them to the login page
	if ( (!empty($_COOKIE[AUTH_COOKIE]) &&
				!wp_validate_auth_cookie($_COOKIE[AUTH_COOKIE])) ||
			(empty($_COOKIE[AUTH_COOKIE])) ) {
		nocache_headers();

		wp_redirect(get_option('siteurl') . '/wp-login.php?redirect_to=' . urlencode($_SERVER['REQUEST_URI']));
		exit();
	}
}
endif;

if ( !function_exists('wp_salt') ) :
function wp_salt() {
	global $wp_default_secret_key;
	$secret_key = '';
	if ( defined('SECRET_KEY') && ('' != SECRET_KEY) && ( $wp_default_secret_key != SECRET_KEY) )
		$secret_key = SECRET_KEY;

	if ( defined('SECRET_SALT') ) {
		$salt = SECRET_SALT;
	} else {
		$salt = get_option('secret');
		if ( empty($salt) ) {
			$salt = wp_generate_password();
			update_option('secret', $salt);
		}
	}

	return apply_filters('salt', $secret_key . $salt);
}
endif;

if ( !function_exists('wp_hash') ) :
function wp_hash($data) {
	$salt = wp_salt();

	return hash_hmac('md5', $data, $salt);
}
endif;
?>