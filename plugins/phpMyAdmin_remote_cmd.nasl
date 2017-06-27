#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15478);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");

 script_cve_id("CVE-2004-2630");
 script_bugtraq_id(11391);
 script_osvdb_id(10715);
 
 script_name(english:"phpMyAdmin < 2.6.0-pl2 Unspecified Arbitrary Command Execution");
 script_summary(english:"Checks the version of phpMyAdmin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that may allow
arbitrary command execution." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of phpMyAdmin is between
2.5.0 and 2.6.0-pl1.  Such versions may allow an authenticated, remote
attacker to run arbitrary commands subject to the privileges of the
web server due to the way external MIME-based transformations are
handled. 

Note that successful exploitation requires that PHP's 'safe_mode' be
disabled and that the administrator not only prepare a special table
for keeping some information but also specify it in a configuration." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2004-2.php" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=414281" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.6.0-pl2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpMyAdmin", "www/PHP");
 exit(0);
}

# Check starts here
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if ( ereg(pattern:"^2\.(5\..*|6\.0$|6\.0-pl1)", string:ver) ) security_warning(port);
}
