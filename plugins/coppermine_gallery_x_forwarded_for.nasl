#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18083);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1172");
  script_bugtraq_id(13218);
  script_osvdb_id(15672);

  script_name(english:"Coppermine Photo Gallery init.inc.php X-Forwarded-For XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the version of Coppermine Photo
Gallery installed on the remote host is affected by a cross-site
scripting vulnerability when logging user comments.  A user with
access to the comments module can exploit this flaw using a
specially crafted 'X-Forwarded-For' header to steal an admin's cookie
when he views the application logs or to launch other types of cross-
site scripting attacks against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/396080" );
 script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/forum/index.php?topic=17134" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Coppermine Photo Gallery version 1.3.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/18");
 script_cvs_date("$Date: 2015/01/23 22:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for X-Forwarded-For Logging Vulnerability in Coppermine Photo Gallery");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("coppermine_gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: catches versions like "1.3.0-Nuke" too.
  if (ver =~ "^(0|1\.([0-2]|3\.[0-2]([^0-9]|$)))")
  {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
