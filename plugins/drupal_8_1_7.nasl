#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92495);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/03 14:18:40 $");

  script_cve_id("CVE-2016-5385");
  script_bugtraq_id(91821);
  script_osvdb_id(141667);
  script_xref(name:"CERT", value:"797896");

  script_name(english:"Drupal 8.x < 8.1.7 PHP HTTP_PROXY Environment Variable Namespace Collision Vulnerability (httpoxy)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 8.x prior
to 8.1.7. It is, therefore, affected by a man-in-the-middle
vulnerability known as 'httpoxy' due to a failure to properly resolve
namespace conflicts in accordance with RFC 3875 section 4.1.18. The
HTTP_PROXY environment variable is set based on untrusted user data in
the 'Proxy' header of HTTP requests. The HTTP_PROXY environment
variable is used by some web client libraries to specify a remote
proxy server. An unauthenticated, remote attacker can exploit this,
via a crafted 'Proxy' header in an HTTP request, to redirect an
application's internal HTTP traffic to an arbitrary proxy server where
it may be observed or manipulated.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2016-003");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.1.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);
fix = FALSE ;


if (version == "8")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (version =~ "^8\.")
{
  if (ver_compare(ver:version,fix:"8.1.7",strict:FALSE) < 0)
    fix = "8.1.7";
  else
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
}

if (!fix)
  audit(AUDIT_WEB_APP_NOT_INST, app + " 8.x", port);

items = make_array("Installed version", version,
                   "Fixed version", fix,
                   "URL", url
                  );

order = make_list("URL", "Installed version", "Fixed version");
report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra: report
);
