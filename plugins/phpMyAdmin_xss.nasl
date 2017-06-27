#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15770);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");

 script_cve_id("CVE-2004-1055");
 script_bugtraq_id(11707);
 script_osvdb_id(11930, 11931, 11932, 12238);

 script_name(english:"phpMyAdmin < 2.6.0-pl3 Multiple XSS");
 script_summary(english:"Checks the version of phpMyAdmin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin installed on the remote host is vulnerable
to cross-site scripting attacks through various parameters and
scripts.  With a specially crafted URL, an attacker can cause
arbitrary code execution resulting in a loss of integrity." );
 # http://web.archive.org/web/20070812185201/http://www.netvigilance.com/html/advisory0005.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72408672" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.6.0-pl3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/18");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

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
if (!can_host_php(port:port) ) exit(0);


# Check an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if ( ereg(pattern:"^(2\.[0-5]\..*|2\.6\.0|2\.6\.0-pl[12]([^0-9]|$))", string:ver))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
