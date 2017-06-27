#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18447);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-1948");
  script_bugtraq_id(13907);
  script_osvdb_id(17243, 17244);

  script_name(english:"Invision Gallery < 1.3.1 Multiple SQL Injections");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable 
to multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Invision Gallery, a community-based photo
gallery plugin for Invision Power Board. 

The version installed on the remote host fails to properly sanitize
user-supplied data through several parameters, making it prone to
multiple SQL injection and cross-site scripting vulnerabilities. 
These flaws may allow an attacker to delete images and/or albums,
discover password hashes, and even affect UPDATE database queries." );
  # http://web.archive.org/web/20100905003631/http://www.gulftech.org/?node=research&article_id=00079-06092005
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c98d6999" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Gallery 1.3.1 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/09");
 script_cvs_date("$Date: 2015/02/03 17:40:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:invision_power_services:invision_gallery");
script_end_attributes();

  script_summary(english:"Checks for multiple input validation vulnerabilities in Invision Gallery");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the SQL injection vulnerabilities.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "act=module&",
      "module=gallery&",
      "cmd=editcomment&",
      # nb: look for this exploit string later.
      "comment='", SCRIPT_NAME
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  if (
    "an error in your SQL syntax" >< res &&
    egrep(
      string:res, 
      pattern:string("SELECT \* FROM .*gallery_comments WHERE pid=&amp;#39;", SCRIPT_NAME)
    )
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
