#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76253);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/12 18:55:23 $");

  script_cve_id("CVE-2013-5954");
  script_bugtraq_id(66251);
  script_osvdb_id(104549);

  script_name(english:"Revive Adserver < 3.0.5 Multiple CSRF Vulnerabilities");
  script_summary(english:"Checks the version of Revive Adserver.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple CSRF vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Revive Adserver install hosted on
the remote web server is affected by multiple cross-site request
forgery (CSRF) vulnerabilities. This can allow an attacker to delete
data and cause service disruptions by enticing an authenticated user
to follow a crafted URL.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.revive-adserver.com/security/revive-sa-2014-001/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:revive-adserver:revive_adserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("revive_adserver_detect.nbin");
  script_require_keys("www/PHP", "www/revive_adserver");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "Revive Adserver";

install = get_install_from_kb(
  appname : "revive_adserver",
  port    : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_url = build_url(port:port, qs:dir + "/index.php");
version = install["ver"];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);

fix = "3.0.5";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+ '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
