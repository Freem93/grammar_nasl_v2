#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14188);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2004-2257");
 script_bugtraq_id(10813);
 script_osvdb_id(8240);

 script_name(english:"phpMyFAQ Image Upload Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows for
unauthorized file uploads." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyFAQ on the remote host contains a flaw that could
allow an attacker without authorization to upload and delete arbitrary
images on the remote host.  An attacker may exploit this problem to
deface the remote website." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/advisory_2004-07-27.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyFAQ 1.4.0a or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/27");
 script_cvs_date("$Date: 2014/04/25 17:36:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmyfaq:phpmyfaq");
script_end_attributes();

 script_summary(english:"Check the version of phpMyFAQ");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpmyfaq_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpmyfaq");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "(0\.|1\.([0-3]\.|4\.0[^a]))") security_hole(port);
}
