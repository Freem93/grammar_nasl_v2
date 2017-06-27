#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18300);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-1608");
  script_bugtraq_id(13539);
  script_osvdb_id(16346);

  script_name(english:"PostNuke AutoTheme Module Multiple Unspecified Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from multiple
issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of AutoTheme for PostNuke on the
remote host suffers from multiple, unspecified vulnerabilities
affecting the 'Blocks' module.  Reportedly, some of these issues may
allow a remote attacker to gain unauthorized access to the remote
host. 

Note that the recommended security fix does not alter AutoTheme's
banner so if you know for certain that it's been applied, treat this
as a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://community.postnuke.com/Article2687.htm" );
 script_set_attribute(attribute:"solution", value:
"Apply the Blocks module Security Fix referenced in the URL or upgrade
to a newer version of the software when available." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/06");
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:spidean:autotheme");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:spidean:at-lite");
 script_end_attributes();
 
  script_summary(english:"Checks for multiple unspecified vulnerabilities in AutoTheme PostNuke module");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php: 1);

# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # Check for AutoTheme's banner.
  pat = "^\*+ (AutoTheme|AT-Lite) ([^*]+) \*+$";
  matches = egrep(string:res, pattern:pat, icase:TRUE);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      banner = eregmatch(pattern:pat, string:match);
      # Extract the product and version number.
      if (!isnull(banner)) {
        prod = banner[1];
        ver = banner[2];

        # Check whether the software is vulnerable.
        if (
          (prod =~ "AutoTheme" && ver =~ "^(0\.|1\.([0-6][^0-9]|7\.0))") ||
          (prod =~ "AT-Lite" && ver =~ "^\.([0-7][^0-9]?|8$)")
        ) {
          security_hole(port);
          exit(0);
        }
      }
    }
  }
}
