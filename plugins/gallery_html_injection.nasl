#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15624);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/05/24 02:02:50 $");

  script_cve_id("CVE-2004-1106");
  script_bugtraq_id(11602);
  script_osvdb_id(11340);

  script_name(english:"Gallery Unspecified HTML Injection");
  script_summary(english:"Checks for the version of Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running a PHP application that is affected by
an HTML injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server has a version of Gallery that could allow an
attacker to inject arbitrary HTML tags via unspecified vectors."
  );
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/node/142");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.4.4-pl3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

  script_dependencie("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

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
version = install["ver"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Gallery", install_url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Versions < 1.4.4-pl3 are affected
if (
  version =~ "^0\." ||
  version =~ "^1\.([0-3]|4\.([0-3]|4$|4-pl[0-2]))([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.4.4-pl3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", install_url, version);
