=== LDAP Authenticator ===
Contributors: cajus
Donate link: https://ferdi.naasa.net/url/cajus/donate.html
Tags: authentication, automatic, plugin, plugins, profile, register
Requires at least: 2.9
Tested up to: 2.9
Stable tag: 1.0

This plugin provides a variable way to use LDAP services for authentication and role synchronization.

== Description ==

Once installed, this plugin will authenticate against an LDAP server. It uses a user defined search
filter to lookup the users distinguished name (DN) and uses that for the final authentication.

Additionally, it is able to synchronize users roles (i.e. Contributor, Administrator, etc.) for
LDAP based users. Put them in a posixGroup, groupOfNames, organizationalRole, etc and map an
attribute to be used as the final role. This mapping gets synchronized every time the user
authenticates himself to WordPress.

Features:

*   Userdefined user lookup filters
*   Userdefined role lookup filters
*   Enforce LDAP only roles
*   Enforce LDAP only users (but keep local administrators)
*   Fallback LDAP servers

== Installation ==

This section describes how to install the plugin and get it working.

1. Upload `wp-ldap-auth` directory to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Make your settings in the 'Plugins/LDAP Configuration' menu in WordPress

== Frequently Asked Questions ==

= Why another LDAP authenticator for WordPress? =

Everyone seems to do another authenticator which is fitting the current needs. So do I ;-)

Well -- I think the main difference is that you can use various LDAP services with special directory
layouts with this implementation.

= I use TLS/SSL connections to my LDAP service. Why does it fail? =

PHP uses the ldap.conf to get more information on how to handle SSL connections. Consult
your ldap.conf(5) manual page and set the TLS options according to your setup.

== Screenshots ==

1. Administrative interface

== Changelog ==

= 1.0 =
* Initial release

== Upgrade Notice ==

= 1.0 =
Since this is the initial release, there is no need to do an upgrade.
