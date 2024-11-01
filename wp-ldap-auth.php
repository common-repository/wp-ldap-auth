<?php
/*
Plugin Name: LDAP Authenticator
Plugin URI: http://www.naasa.net
Description: This plugin provides a variable way to use LDAP services for authentication and role synchronization.
Version: 1.0
Author: Cajus Pollmeier
Author URI: http://www.naasa.net
*/
/*  Copyright 2009 Cajus Pollmeier  (email : cajus@naasa.net)

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

require_once(ABSPATH . WPINC . '/registration.php');


/**
 * Initialize LDAP authenticator plugin.
 *
 * @access private
 */
function ldap_init() {
    add_action('admin_menu', 'ldap_config_page');
    ldap_admin_warnings();
    $plugin_dir = basename(dirname(__FILE__));
    if(function_exists('load_plugin_textdomain')) {
        load_plugin_textdomain('wp-ldap-auth', false,
                               dirname(plugin_basename(__FILE__))."/languages"); 
    }
}
add_action('init', 'ldap_init');


/**
 * Add configuration page to the Plugin menu.
 *
 * @access private
 */
function ldap_config_page() {
    if ( function_exists('add_submenu_page') ){
        add_submenu_page('plugins.php', __('LDAP Configuration', 'wp-ldap-auth'),
                         __('LDAP Configuration', 'wp-ldap-auth'),
                        'manage_options', 'ldap-config', 'ldap_conf');
    }
}


/**
 * Show and Handle configuration page.
 *
 * @access private
 */
function ldap_conf() {
    if ( isset($_POST['submit']) ) {

        // Bail out if we've no permission to manage anything
        if ( function_exists('current_user_can') && !current_user_can('manage_options') ) {
            die(__('Cheatin&#8217; uh?'));
        }

        // Error messages go here
        $messages= array();
        
        // Store available checkboxes
        update_option('ldap_scope', isset($_POST['ldap_scope'])?'sub':'one');
        update_option('ldap_v3', isset($_POST['ldap_v3'])?'true':'false');
        update_option('ldap_auto_create', isset($_POST['ldap_auto_create'])?'true':'false');
        update_option('ldap_only_login', isset($_POST['ldap_only_login'])?'true':'false');
        
        // Store and check fields
        foreach (array('ldap_uris', 'ldap_base', 'ldap_dn', 'ldap_password', 'ldap_account_filter',
                       'ldap_role_filter', 'ldap_role_filter_attribute',
                       'ldap_default_role', 'ldap_mail_attribute') as $option) {
            if (isset($_POST[$option])) {
                if (function_exists("validate_$option")){
                    $func= "validate_$option";
                    $messages[$option]= $func(htmlspecialchars($_POST[$option]));
                }
                update_option($option, htmlspecialchars($_POST[$option]));
            }
        }

    }

    // Display save message
    if ( !empty($_POST['submit'] ) ) : ?>
<div id="message" class="updated fade"><p><strong><?php _e('Options saved.') ?></strong></p></div>
<?php endif; ?>
<div class="wrap">
<h2><?php _e('LDAP Configuration', 'wp-ldap-auth'); ?></h2>
<div class="narrow">
<form action="" method="post" id="ldap-conf" style="margin: auto; width: 500px; ">
<p><?php printf(__('For centralized management of users and their authentication, a <a href="%1$s">LDAP Server</a> can greatly reduce the overhead with account creation and role assignment. If you don\'t have a LDAP server yet, you can find information about it at <a href="%2$s">OpenLDAP.org</a>.', 'wp-ldap-auth'), 'http://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol', 'http://www.openldap.org'); ?></p>
<h3><?php _e('LDAP Connection', 'wp-ldap-auth'); ?></h3>

<h4><label for="ldap_uris"><?php _e('Server URIs', 'wp-ldap-auth'); ?></label></h4>
<p><?php _e('This option takes a comma separated list of LDAP URIs that describe the hostname/IP and port of your LDAP server(s).', 'wp-ldap-auth'); ?></p>
<p><input id="ldap_uris" name="ldap_uris" type="text" size="25" maxlength="60" value="<?php echo get_option('ldap_uris'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
<?php if (!empty($messages['ldap_uris'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_uris'];?></p>
<?php }?>
<p><label><input name="ldap_v3" id="ldap_v3" value="true" type="checkbox" <?php if ( get_option('ldap_v3') == 'true' ) echo ' checked="checked" '; ?> /> <?php _e('Use LDAP v3', 'wp-ldap-auth'); ?></label></p>

<h4><label for="ldap_base"><?php _e('Base DN', 'wp-ldap-auth'); ?></label></h4>
<p><?php _e('The DN which is used as the base for account and group queries.', 'wp-ldap-auth'); ?></p>
<p><input id="ldap_base" name="ldap_base" type="text" size="25" maxlength="60" value="<?php echo get_option('ldap_base'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
<?php if (!empty($messages['ldap_base'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_base'];?></p>
<?php }?>

<p><label><input name="ldap_scope" id="ldap_scope" value="sub" type="checkbox" <?php if ( get_option('ldap_scope') == 'sub' ) echo ' checked="checked" '; ?> /> <?php _e('Search for matching entries in subtrees', 'wp-ldap-auth'); ?></label></p>
<h4><label for="ldap_dn"><?php _e('Bind DN', 'wp-ldap-auth'); ?></label></h4>
<p><?php _e('Depending on your LDAP setup, it might be required to do authenticated searches. In this case you need to specifiy the DN and the password which is used to bind to the LDAP server. If anonymous binds are sufficient, leave these fields empty.', 'wp-ldap-auth'); ?></p>
<p><input id="ldap_dn" name="ldap_dn" type="text" size="25" maxlength="60" value="<?php echo get_option('ldap_dn'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
<?php if (!empty($messages['ldap_dn'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_dn'];?></p>
<?php }?>

<h4><label for="ldap_password"><?php _e('Bind Password', 'wp-ldap-auth'); ?></label></h4>
<p><input id="ldap_password" name="ldap_password" type="text" size="25" maxlength="60" value="<?php echo get_option('ldap_password'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
        <p class="submit"><input type="submit" name="submit" value="<?php _e('Update options &raquo;', 'wp-ldap-auth'); ?>" /></p>

<h3><?php _e('Filters &amp; mapping', 'wp-ldap-auth'); ?></h3>
<h4><label for="ldap_account_filter"><?php _e('Account Filter', 'wp-ldap-auth'); ?></label></h4>
<p><?php _e('The LDAP plugin will use this filter to locate the user in the LDAP tree. You can use the keyword %user for the currently used login name. The resulting DN will be used for the proper password verification.', 'wp-ldap-auth'); ?></p>
<p><input id="ldap_account_filter" name="ldap_account_filter" type="text" size="35" maxlength="60" value="<?php echo get_option('ldap_account_filter'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
<?php if (!empty($messages['ldap_account_filter'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_account_filter'];?></p>
<?php }?>

<h4><label for="ldap_role_filter"><?php _e('Role Filter', 'wp-ldap-auth'); ?></label></h4>
<p><?php _e('If you want to assign WordPress roles depending on LDAP attributes and user memberships, you can use the <b>Role Filter</b> in combination with <b>Role Filter Attribute</b> to define the target role automatically. Use the keyword %user or %userdn in order to search for the role. The contents of the <b>Role Filter Attribute</b> will be used for the role. The <b>Default Role</b> will be used if the resulting value is inavlid or not exisistant. Leave it empty to force users to have a LDAP assigned role.', 'wp-ldap-auth'); ?></p>
<p><input id="ldap_role_filter" name="ldap_role_filter" type="text" size="35" maxlength="60" value="<?php echo get_option('ldap_role_filter'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
<?php if (!empty($messages['ldap_role_filter'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_role_filter'];?></p>
<?php }?>

<h4><label for="ldap_role_filter_attribute"><?php _e('Role Filter Attribute', 'wp-ldap-auth'); ?></label></h4>
<p><input id="ldap_role_filter_attribute" name="ldap_role_filter_attribute" type="text" size="25" maxlength="60" value="<?php echo get_option('ldap_role_filter_attribute'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
<?php if (!empty($messages['ldap_role_filter_attribute'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_role_filter_attribute'];?></p>
<?php }?>

<h4><label for="ldap_default_role"><?php _e('Default Role', 'wp-ldap-auth'); ?></label></h4>
<p><select id="ldap_default_role" name="ldap_default_role" size="1">
<option></option>
<?php
  $types= array("Administrator", "Editor", "Author", "Contributor", "Subscriber");
  $current= get_option('ldap_default_role');
  foreach ($types as $type) {
    echo "<option".($current==$type?' selected':'').">$type</option>";
  }
?>
</select>
<?php if (!empty($messages['ldap_default_role'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_default_role'];?></p>
<?php }?>
        <p class="submit"><input type="submit" name="submit" value="<?php _e('Update options &raquo;', 'wp-ldap-auth'); ?>" /></p>

<h3><?php _e('Account Autocreation', 'wp-ldap-auth'); ?></h3>
<p><?php _e('If you enable account autocreation, you must specify the users LDAP <b>Mail Attribute</b> to get the mail address from.', 'wp-ldap-auth'); ?></p>
<p><label><input name="ldap_auto_create" id="ldap_auto_create" value="true" type="checkbox" <?php if ( get_option('ldap_auto_create') == 'true' ) echo ' checked="checked" '; ?> /> <?php _e('Automatically create non existing users', 'wp-ldap-auth'); ?></label></p>
<p><label><input name="ldap_only_login" id="ldap_only_login" value="true" type="checkbox" <?php if ( get_option('ldap_only_login') == 'true' ) echo ' checked="checked" '; ?> /> <?php _e('Only allow login for local admins and users that exist in LDAP', 'wp-ldap-auth'); ?></label></p>

<h4><label for="ldap_mail_attribute"><?php _e('Mail Attribute', 'wp-ldap-auth'); ?></label></h4>
<p><input id="ldap_mail_attribute" name="ldap_mail_attribute" type="text" size="25" maxlength="60" value="<?php echo get_option('ldap_mail_attribute'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>
<?php if (!empty($messages['ldap_mail_attribute'])) { ?>
<p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;"><?php echo $messages['ldap_mail_attribute'];?></p>
<?php }?>

        <p class="submit"><input type="submit" name="submit" value="<?php _e('Update options &raquo;', 'wp-ldap-auth'); ?>" /></p>

</form>
</div>
</div>
<?php
}


/**
 * Show warnings if not configured.
 *
 * This will show a warning message on top of the screen if the plugin has
 * not been set up correctly.
 *
 * @access private
 */
function ldap_admin_warnings() {
    if ( !isset($_POST['submit']) && !ldap_get_connection() ) {
        function ldap_warning() {
            echo "<div id='ldap-warning' class='updated fade'><p><strong>".__('LDAP authentication is almost ready.', 'wp-ldap-auth')."</strong> ".sprintf(__('You must <a href="%1$s">configure your LDAP server</a> for it to work.', 'wp-ldap-auth'), "plugins.php?page=ldap-config")."</p></div>";
        }

        add_action('admin_notices', 'ldap_warning');
        return;
    }
}


/**
 * Validate LDAP URI provided by administrator
 *
 * Do a simple regular expression check if the provided value is
 * in fact a LDAP URI.
 *
 * @param  string  $option LDAP URI string
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_uris($option)
{
    $uris= explode(',', $option);
    foreach ($uris as $uri) {
        if(!preg_match("/^ldap[si]?:\/\/[0-9a-z_.-]+(:[0-9]+)?$/", $uri)){
            return sprintf(__("Invalid URI: '%s'", 'wp-ldap-auth'), $uri);
        }
    }
    return null;
}


/**
 * Validate LDAP Base provided by administrator
 *
 * Do a simple regular expression check if the provided value is
 * in fact a LDAP Base.
 *
 * @param  string  $option LDAP Base DN
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_base($option)
{
    if (!preg_match("/^[a-z0-9]+=[^=,]+(,[a-z0-9]+=[^=,]+)+$/i", $option)) {
        return __("Invalid DN format.", 'wp-ldap-auth');
    }
    return null;
}


/**
 * Validate LDAP DN provided by administrator
 *
 * Do a simple regular expression check if the provided value is
 * in fact a LDAP DN.
 *
 * @param  string  $option LDAP DN
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_dn($option)
{
    // Empty is OK, because we might want anonymous binds
    if (empty($option)){
        return null;
    }

    // Just continue with stock validate_ldap_base function
    return validate_ldap_base($option);
}


/**
 * Validate LDAP Filter provided by administrator
 *
 * Do a simple check if we've the %user keyword in the filter.
 * Without, it will not make much sense.
 *
 * @param  string  $option LDAP Filter
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_account_filter($option)
{
    // Check for %user
    if (!preg_match('/%user/', $option)){
        return __('%user is needed to define a proper search filter.', 'wp-ldap-auth');
    }

    return null;
}


/**
 * Validate LDAP Role Filter provided by administrator
 *
 * Do a simple check if we've the %user or %userdn keyword in the filter.
 * Without, it will not make much sense.
 *
 * @param  string  $option LDAP Filter
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_role_filter($option)
{
    // Empty is OK, because we might want to use just the
    // default role.
    if (empty($option)) {
        return null;
    }

    // Check for %user and/or %userdn
    if (!preg_match('/%user/', $option) && !preg_match('/%userdn/', $option) ){
        return __('%user or %userdn is needed to define a proper search filter.', 'wp-ldap-auth');
    }

    return null;
}


/**
 * Validate LDAP Role Filter Attribute provided by administrator
 *
 * If a Role Filter has been defined, we need the Role Filter
 * Attribute to evaluate the resulting role. Check if the
 * conditions are OK. And if they're OK, check against LDAP
 * attribute syntax.
 *
 * @param  string  $option LDAP Filter Attribute
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_role_filter_attribute($option)
{
    // Empty is OK if the role filter is not set
    if (empty($option) && get_option('ldap_role_filter') == ''){
        return null;
    }

    // But if the filter is specified, we need the attribute
    // to resolve the role. Bail out if not.
    if ($option == "") {
        return __("Role Filter Attrbute needed if filter is specified.", 'wp-ldap-auth');
    }

    // Check for LDAP attribute syntax
    if (!preg_match('/^[a-z0-9]+$/i', $option)){
        return __("Invalid attribute name.", 'wp-ldap-auth');
    }

    return null;
}


/**
 * Validate LDAP Default Role
 *
 * If no Role Filter has been defined, we need the Default
 * Role to be able to assign a role, finally. If provided,
 * check for valid WordPress role name.
 *
 * @param  string  $option LDAP Default Role
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_default_role($option)
{
    // If no LDAP Role Filter is specified, we need the Default Role
    if ($option == "" && get_option('ldap_role_filter') == '') {
        return __("Default Role needs to be specified if no Role Filter has been set.", 'wp-ldap-auth');
    }

    // Empty is ok because it forces us to be inside an LDAP assignment
    if ($option == "") {
        return null;
    }

    // Check if the role is a valid role name
    $valid_roles= array("Administrator", "Editor", "Author", "Contributor", "Subscriber");
    if (!in_array($option, $valid_roles)){
        return __("Invalid role name. Administrator, Editor, Author, Contributor or Subscriber expected.", 'wp-ldap-auth');
    }

    return null;
}


/**
 * Validate LDAP Mail Attribute
 *
 * If the LDAP Authenticator plugin should create accounts
 * automatically, we need the users mail attribute to fill
 * it into the user creation process. Checks if the attribute
 * is valid.
 *
 * @param  string  $option LDAP Mail Attribute
 * @return string  Error message or NULL if OK
 * @access private
 */
function validate_ldap_mail_attribute($option)
{
    // If the autocreation is disabled, just pass the check
    if (get_option('ldap_auto_create') != "true") {
        return null;
    }

    // If not, check for valid attribute name
    if (!preg_match('/^[a-z0-9]+$/i', $option)){
        return __("Invalid attribute name.", 'wp-ldap-auth');
    }

    return null;
}


/**
 * Activate the plugin and set default values
 *
 * @access private
 */
function ldap_activation_hook()
{
    // Store initial settings
    add_option("ldap_uris", "ldap://ldap.example.net");
    add_option("ldap_base", "dc=example,dc=net");
    add_option("ldap_dn", "");
    add_option("ldap_v3", "true");
    add_option("ldap_password", "");
    add_option("ldap_scope", "sub");
    add_option("ldap_account_filter", "(&(objectClass=posixAccount)(uid=%user))");
    add_option("ldap_mail_attribute", "mail");
    add_option("ldap_role_filter", "(&(objectClass=organizationalRole)(roleOccupant=%userdn))");
    add_option("ldap_role_filter_attribute", "cn");
    add_option("ldap_default_role", "");
    add_option("ldap_auto_create", "true");
    add_option("ldap_only_login", "true");
}
register_activation_hook( __FILE__, 'ldap_activation_hook' );


/**
 * Override authentication if function exists
 */
if (!function_exists('wp_authenticate')){

    /**
     * WordPress Authentication hook
     *
     * Add LDAP authentication to ordinary WordPress authentication.
     * Check if the user exists in DB. If not, try to connect to LDAP
     * and evaluate if the user should be created by taking the settings
     * into account. Migrate a user role if the role is based on LDAP
     * only.
     *
     * @param  string  $username Username entered in login dialog
     * @param  string  $password Password entered in login dialog
     * @return string  Error message or NULL if OK
     * @access private
     */
    function wp_authenticate($username, $password) {

        // Normalize input
        $password= stripslashes($password);
        $username= sanitize_user($username);

        // Bail out if user or password fields are empty
        if ( $username == '') {
            return new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
        }
        if ( $password == '') {
            return new WP_Error('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
        }
 
        // Load user object
        $user= get_userdatabylogin($username);

        // No WordPress user yet, consult LDAP if autocreation is specified
        if ( !$user && get_option('ldap_auto_create') == 'true') {

            // Create LDAP connection
            $ldap= ldap_get_connection();
            if (!$ldap) {
                return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Cannot connect to LDAP server.', 'wp-ldap-auth'));
            }

            // Resolve user DN, WordPress does not check the case of usernames, so there's no
            // further investigation about attribut cases needed.
            $dn= ldap_get_user_info($ldap, $username, array('sn', 'givenName', get_option('ldap_mail_attribute')), $result);
            if (!$dn) {
                return new WP_Error('invalid_username', __('<strong>ERROR</strong>: Invalid username.', 'wp-ldap-auth'));
            }

            // Validate user password
            if (!ldap_check_password($dn, $password)) {
                return new WP_Error('incorrect_password', __('<strong>ERROR</strong>: Incorrect password.', 'wp-ldap-auth'));
            }

            // Evaluate user role
            $ldap_role= ldap_get_user_role($ldap, $username, $dn);
            $role= $ldap_role == ""?get_option('ldap_default_role'):$ldap_role;

            // If role != valid rolesInvalid username -> invalid username
            if (validate_ldap_default_role($role) != null) {
                do_action( 'wp_login_failed', $username );
                return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: No LDAP resovable role.', 'wp-ldap-auth'));
            }

            // Check attributes
            foreach (array('sn', 'givenname', get_option('ldap_mail_attribute')) as $attr) {
              if (!isset($result[$attr][0])) {
                do_action( 'wp_login_failed', $username );
                return new WP_Error('invalid_username', __("<strong>ERROR</strong>: Autocreation failed. No $attr attribute.", 'wp-ldap-auth'));
              }
            }

            // Finally create user with some not resolvable password
            $userData = array( 'user_pass'     => md5(md5(microtime()).session_id()),
                               'user_login'    => $username,
                               'user_nicename' => $result['givenname'][0].' '.$result['sn'][0],
                               'user_email'    => $result[get_option('ldap_mail_attribute')][0],
                               'display_name'  => $result['givenname'][0].' '.$result['sn'][0],
                               'first_name'    => $result['givenname'][0],
                               'last_name'     => $result['sn'][0],
                               'role'          => strtolower($role));
            wp_insert_user($userData);

            // Reload user data to feed it later on...
            $user= get_userdatabylogin($username);
        }

        // Compare username to be sure
        if (strtolower($user->user_login) != strtolower($username)){
            do_action( 'wp_login_failed', $username );
            return new WP_Error('invalid_username', __('<strong>ERROR</strong>: Invalid username.', 'wp-ldap-auth'));
        }

        // WordPress magic
        $user = apply_filters('wp_authenticate_user', $user, $password);
        if ( is_wp_error($user) ) {
            do_action( 'wp_login_failed', $username );
            return $user;
        }

        // Check authentication against LDAP before trying something else
        if ( !wp_check_password($password, $user->user_pass, $user->ID) ) {

            // Does not validate to WP database, does the password validate against LDAP?
            $ldap= ldap_get_connection();
            if (!$ldap) {
                return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Cannot connect to LDAP server.', 'wp-ldap-auth'));
            }

            // Resolve user DN
            $dn= ldap_get_user_info($ldap, $username);
            if (!$dn) {
                return new WP_Error('invalid_username', __('<strong>ERROR</strong>: Invalid username.', 'wp-ldap-auth'));
            }

            // Validate user password
            if (!ldap_check_password($dn, $password)) {
                return new WP_Error('incorrect_password', __('<strong>ERROR</strong>: Incorrect password.', 'wp-ldap-auth'));
            }

            // Maybe we need to update the role
            $user_object= new WP_User($user->ID);

            // Evaluate user role. This will bail out if there's no role assigned from
            // LDAP and no default role.
            $ldap_role= ldap_get_user_role($ldap, $username, $dn);
            $role= $ldap_role == ""?get_option('ldap_default_role'):$ldap_role;
            if (validate_ldap_default_role($role) != null) {
                do_action( 'wp_login_failed', $username );
                return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: No LDAP resovable role.', 'wp-ldap-auth'));
            }

            // After resolving the role, assign it - if not already set
            if (!in_array(strtolower($role), $user_object->roles)){
                $user_object->set_role($role);
            }

            // Finally go on with the user object
            return $user_object;
        }

        // Maybe we only want admins to get a login in LDAP mode...
        $user_object= new WP_User($user->ID);
        if((get_option("ldap_only_login") == "true") && !in_array("administrator", $user_object->roles)) {
            do_action( 'wp_login_failed', $username );
            return new WP_Error('invalid_username', __('<strong>ERROR</strong>: Invalid username.', 'wp-ldap-auth'));
        }

        return $user_object;
    }


    /**
     * Get LDAP connection
     *
     * The LDAP conection will be taken from one of the supplied URIs, starting
     * with the first one. If all LDAP servers fail the connect request, bail
     * out.
     *
     * @return object  LDAP handle
     * @access private
     */
    function ldap_get_connection()
    {
        // Try all uris until one server is responding
        $uris= explode(',', get_option('ldap_uris'));
        $ds= null;
        $bind= false;
        foreach ($uris as $uri) {
            $ds= ldap_connect($uri);

            // Set LDAP version if requested, if it does not work, use next server
            if (get_option('ldap_v3') == 'true'){
                if (!ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3)) {
                    next;
                }
            }

            // Anonymous bind?
            if (get_option('ldap_dn') == ''){
                $bind= @ldap_bind($ds);
            } else {
                $bind= @ldap_bind($ds, get_option('ldap_dn'), get_option('ldap_password'));
            }

            // Server down? Try next...
            if (!$bind && ldap_errno($ds) == 81) {
                next;
            }
        }

        return $bind?$ds:null;
    }


    /**
     * Retrieve user information from LDAP
     *
     * @param  object  $ldap LDAP handle
     * @param  string  $username WordPress user name
     * @param  array   $attributes List of attributes to put into $result
     * @param  ref     $result Reference to the resulting LDAP entry
     * @return array   LDAP entries or NULL if failed  
     * @access private
     */
    function ldap_get_user_info($ldap, $username, $attributes= null, &$result= null) {

        // At least return users DN if attributes are not set
        if (!$attributes) {
            $attributes= array('dn');
        }
        // Search for user, replace %user in filter
        $filter= htmlspecialchars_decode(preg_replace('/%user/', 
                                         ldap_escape_filter($username),
                                         get_option('ldap_account_filter')));

        // Load parameters we need for the search
        $base= htmlspecialchars_decode(get_option('ldap_base'));
        $scope= get_option('ldap_scope');

        // Handle scope
        if ($scope == 'sub') {
            $res= ldap_search($ldap, $base, $filter, $attributes);
        } else {
            $res= ldap_list($ldap, $base, $filter, $attributes);
        }

        // Try to load entries. If zero or not unique, fail.
        $entries= ldap_get_entries($ldap, $res);
        if ($entries['count'] != 1) {
            return (null);
        }

        // Assign result passed by reference
        $result= $entries[0];

        // Return user DN
        return ($entries[0]['dn']);
     }


    /**
     * Bind as the resulting user
     *
     * @param  string   $dn User LDAP DN
     * @param  password $password User password
     * @return bool     false if failed
     * @access private
     */
    function ldap_check_password($dn, $password)
    {
        // Try to get connection, bail out if it fails
        $test= ldap_get_connection();
        if (!$test) {
            return false;
        }

        // Try to bind as specified user dn and password
        $bind= @ldap_bind($test, $dn, $password);
        if (!$bind) {
            return false;
        }

        // Success - we made it
        return true;
     }       


    /**
     * Resolve user role from LDAP entries
     *
     * @param  object   $ldap LDAP handle
     * @param  string   $username User name
     * @param  string   $dn User DN
     * @return string   Role or empty string if there's no role
     * @access private
     */
     function ldap_get_user_role($ldap, $username, $dn)
     {
         // Search for user role, replace %user and %userdn
         $attribute= get_option('ldap_role_filter_attribute');
         $filter= preg_replace( array('/%userdn/', '/%user/'), 
                                array(ldap_escape_filter($dn),
                                      ldap_escape_filter($username)),
                                get_option('ldap_role_filter'));

         // Load search parameters
         $filter= htmlspecialchars_decode($filter);
         $base= htmlspecialchars_decode(get_option('ldap_base'));
         $scope= get_option('ldap_scope');

         // Handle scope
         if ($scope == 'sub') {
             $res= ldap_search($ldap, $base, $filter, array($attribute));
         } else {
             $res= ldap_list($ldap, $base, $filter, array($attribute));
         }

         // Load entries, return if result attribute is set and role is
         // unique
         $entries= ldap_get_entries($ldap, $res);
         if ($entries['count'] == 1 && isset($entries[0][$attribute][0])) {
             return $entries[0][$attribute][0];
         }

         // No role in LDAP, bail out
         return "";
     }


    /**
     * Escape characters that may shred the LDAP filter
     *
     * @param  string   $filter LDAP filter
     * @return string   Sanatized LDAP filter
     * @access private
     */
     function ldap_escape_filter($filter) 
     { 
         return (addcslashes($filter, '()|')); 
     }

}

//vim:tabstop=4:expandtab:shiftwidth=4:filetype=php:syntax:ruler:
?>
