#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69273);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2013-5576");
  script_bugtraq_id(61582);
  script_osvdb_id(95933);
  script_xref(name:"CERT", value:"639620");

  script_name(english:"Joomla! 2.5.x < 2.5.14 / 3.x < 3.1.5 .php. File Upload RCE");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 2.5.x prior to 2.5.14
or 3.x prior to 3.1.5. It is, therefore, affected by a remote code
execution vulnerability due to a failure by the
administrator/components/com_media/helpers/media.php script to
properly validate the extension of an uploaded file. This allows files
with '.php.' extensions to be uploaded and placed in a user-accessible
path. An attacker can exploit this issue, via a direct request to such
an uploaded file, to execute arbitrary PHP code with the privileges of
the web server.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://developer.joomla.org/security/news/563-20130801-core-unauthorised-uploads
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01c258b2");
  # https://www.joomla.org/announcements/release-news/5506-joomla-2-5-14-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3653e23d");
  # https://www.joomla.org/announcements/release-news/5505-joomla-3-1-5-stable-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f239a18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 2.5.14 / 3.1.5 or later. Alternatively,
apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Joomla 1.5.26 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Joomla Media Manager File Upload Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");

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

fix = "2.5.14 / 3.1.5";

# Check granularity
if (version =~ "^2(\.5)?$" || version =~ "^3(\.1)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Versions 2.5.x < 2.5.14 and 3.x < 3.1.5 are vulnerable
if (
  version =~ "^2\.5($|\.([0-9]|1([0-3]))($|[^0-9]))" ||
  version =~ "^3\.0($|[^0-9])" ||
  version =~ "^3\.1($|\.[0-4]($|[^0-9]))"
)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
