#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14324);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2015/01/22 18:36:58 $");
 script_cve_id("CVE-2004-1730", "CVE-2004-1731", "CVE-2004-1734");
 script_bugtraq_id(10993, 10994, 10995);
 script_osvdb_id(9086, 9087, 9088, 9089, 9090, 9091, 9092);

 script_name(english:"Mantis < 0.18.3 / 0.19.0a2 Multiple Vulnerabilities");
 script_summary(english:"Checks for the version of Mantis");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of Mantis contains multiple
flaws that may allow an attacker to use it to perform a mass emailing,
to inject HTML tags in the remote pages, or to execute arbitrary
commands on the remote host if PHP's 'register_globals' setting is
enabled.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109312225727345&w=2");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109313416727851&w=2");
 script_set_attribute(attribute:"solution", value:"Upgrade to Mantis 0.18.3 or 0.19.0a2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/20");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("mantis_detect.nasl");
 script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(ereg(pattern:"^0\.([0-9]\.|1[0-7]\.|18\.[0-2][^0-9]|19\.0 *a[01]([^0-9]|$))", string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 0.18.3 or 0.19.0a2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
