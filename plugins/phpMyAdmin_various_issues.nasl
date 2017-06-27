#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
 script_id(15948);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");

 script_bugtraq_id(11886);
 script_osvdb_id(12330, 12331);
 script_cve_id("CVE-2004-1147", "CVE-2004-1148");

 script_name(english:"phpMyAdmin < 2.6.1-rc1 Multiple Remote Vulnerabilities");
 script_summary(english:"Checks the version of phpMyAdmin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of phpMyAdmin is
vulnerable to one (or both) of the following flaws :

- An attacker may be able to exploit this software to execute
arbitrary commands on the remote host on a server which does not run
PHP in safe mode. 

- An attacker may be able to read arbitrary files on the remote host
through the argument 'sql_localfile' of the file 'read_dump.php'." );
 # http://web.archive.org/web/20051227082942/http://www.exaprobe.com/labs/advisories/esa-2004-1213.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31ea48ff" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Dec/114" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.6.1-rc1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/phpMyAdmin", "www/PHP");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php:TRUE);
kb   = get_kb_item("www/" + port + "/phpMyAdmin");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
# Only 2.4.0 to 2.6.0plX affected
if (matches[1] && ereg(pattern:"^(2\.[45]\..*|2\.6\.0|2\.6\.0-pl)", string:matches[1]))
	security_warning(port);
