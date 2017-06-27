#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86314);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2015-2912");
  script_bugtraq_id(76610);
  script_osvdb_id(127044);
  script_xref(name:"CERT", value:"845332");

  script_name(english:"OrientDB < 2.0.15 / 2.1.1 XSRF");
  script_summary(english:"Checks the version of OrientDB.");

  script_set_attribute(attribute:"synopsis", value:
"The version of OrientDB running on the remote host is affected by a
cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OrientDB running on the remote host is prior to 2.0.15
or 2.1.1. It is, therefore, affected by a cross-site request forgery
(XSRF) vulnerability due to the server allowing JSONP callbacks within
the REST API. An unauthenticated, remote attacker can exploit this,
via a crafted web page that sends a get-request, to gain access to
information about the JSON requests.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/orientechnologies/orientdb/issues/4824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OrientDB version 2.0.15 / 2.1.1 or later. Alternatively,
disable the Studio plug-in to mitigate this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:orientdb:orientdb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("orientdb_detect.nbin");
  script_require_keys("installed_sw/OrientDB");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http_func.inc");

app_name = "OrientDB";
get_install_count(app_name:app_name, exit_if_zero:TRUE); # Stops port branching

port    = get_http_port(default:2480);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url     = build_url2(qs:install['path'],port:port);
studio  = install['studio_enabled'];
fix     = FALSE;
pver    = install['Pre-release'];

# Only affected if studio plug-in is running
if(!studio)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);

if(version =~ "^2\.1(\.|$)" && ver_compare(fix:"2.1.1",  ver:version, strict:FALSE) < 0)
  fix = "2.1.1";
else if(ver_compare(fix:"2.0.15", ver:version, strict:FALSE) < 0)
  fix = "2.0.15";

if(fix)
{
  if(pver)
    version = version + '-' + pver;

  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  Path              : '+url+
             '\n  Installed version : '+version+
             '\n  Fixed version     : '+fix+
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);
