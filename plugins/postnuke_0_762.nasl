#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20969);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-0800", "CVE-2006-0801", "CVE-2006-0802");
  script_bugtraq_id(16752);
  script_osvdb_id(23433, 23434, 23435, 23436);

  script_name(english:"PostNuke < 0.762 Multiple Vulnerabilities");
  script_summary(english:"Checks for admin access bypass issue in PostNuke");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of PostNuke allows an unauthenticated attacker
to gain administrative access to select modules through a simple GET
request.  Additionally, it may be prone to various SQL injection
injection or cross-site scripting attacks as well as unspecified
attacks through the Languages module." );
 script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/33" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Feb/473" );
 script_set_attribute(attribute:"see_also", value:"http://news.postnuke.com/index.php?name=News&file=article&sid=2754" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PostNuke 0.762 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/22");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the admin access bypass issue.
  r = http_send_recv3(method:"GET", item:string(dir, "/admin.php?module=Banners"), port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);


  # There's a problem if we're granted access.
  if ('<a href="admin.php?module=Banners&amp;op=getConfig">Banners configuration' >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
