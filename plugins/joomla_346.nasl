#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87416);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id(
    "CVE-2015-8562",
    "CVE-2015-8563",
    "CVE-2015-8564",
    "CVE-2015-8565"
  );
  script_bugtraq_id(
    79195,
    79199,
    79201,
    79203
  );
  script_osvdb_id(
    131679,
    131680,
    131681,
    131682
  );
  script_xref(name:"EDB-ID", value:"38977");
  script_xref(name:"EDB-ID", value:"39033");

  script_name(english:"Joomla! < 3.4.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is prior to 3.4.6. It
is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to
    improper sanitization of session values. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2015-8562)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to HTTP requests to com_templates not requiring
    multiple steps, explicit confirmation, or a unique token
    when performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    cause the user to perform unspecified actions.
    (CVE-2015-8563)

  - A path traversal vulnerability exists due to improper
    sanitization of user-supplied input via the XML install
    file. (CVE-2015-8564)

  - A path traversal vulnerability exists due to improper
    sanitization of input supplied via user requests.
    (CVE-2015-8565)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5641-joomla-3-4-6-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b06a8fbc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Joomla HTTP Header Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
install_loc =  build_url(port:port, qs:install['path']);
fix = "3.4.6";

# Pull out the purely numeric version
numeric = eregmatch(string:version, pattern:"^([0-9\.]+)($|[^0-9])");

if (empty_or_null(numeric))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

numeric = numeric[1];

if (numeric == "3.4")
  audit(AUDIT_VER_NOT_GRANULAR, app, version);

# Version 1.5.0 - 3.4.5 vulnerable to RCE
if (ver_compare(ver:numeric, fix:"1.5.0", strict:FALSE) >= 0 &&
    ver_compare(ver:numeric, fix:fix, strict:FALSE) < 0)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xsrf:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
