#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21017);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/02/10 16:37:08 $");

  script_cve_id(
    "CVE-2006-1126",
    "CVE-2006-1127",
    "CVE-2006-1128"
  );
  script_bugtraq_id(16940);
  script_osvdb_id(
    59499,
    23596,
    23597
  );

  script_name(english:"Gallery < 2.0.3 IP Spoofing");
  script_summary(english:"Checks for IP spoofing in Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
an IP spoofing issue."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server allows an
attacker to spoof the IP address with a bogus 'X_FORWARDED_FOR' HTTP
header. 

In addition, an authenticated attacker can reportedly leverage this
flaw to launch cross-site scripting attacks by adding comments to a
photo.  The application also reportedly fails to validate a session
id before using it, which can be used to delete arbitrary files on
the remote host subject to the privileges of the web server user id;
however, Nessus has not tested for these additional issues."
  );
  # http://www.gulftech.org/advisories/Gallery%202%20Multiple%20Vulnerabilities/98
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3548c5a5");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426655/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/gallery_2.0.3_released");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 2.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"gallery",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];

init_cookiejar();

ip = "nessus" + rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789");
useragent = "Mozilla/4.0 (compatible; " + SCRIPT_NAME + "; Googlebot)";

r = http_send_recv3(
  method : 'GET',
  item   : dir + "/main.php",
  port   : port,
  add_headers  : make_array("X_FORWARDED_FOR", ip, "User-Agent", useragent),
  exit_on_fail : TRUE
);

# There's a problem if the GALLERYSID cookie has our fake "IP".
val = get_http_cookie(name: "GALLERYSID");

if (egrep(pattern:"google" + ip, string: val)) security_warning(port);
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
