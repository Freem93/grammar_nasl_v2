#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15651);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(11622);

 script_name(english:"Mantis < 0.19.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of Mantis suffers from
several information disclosure vulnerabilities that could allow an
attacker to view stats of all projects or to receive information for a
project after the malicious user was removed from it." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mantisbt.org/view.php?id=3117" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mantisbt.org/view.php?id=4341" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 0.19.1 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/09");
 script_cvs_date("$Date: 2015/01/22 18:36:58 $");
 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:mantisbt:mantisbt");
 script_end_attributes();


 script_summary(english: "Checks for the version of Mantis");

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

if(ereg(pattern:"^0\.(0?[0-9]\.|1([0-8]\.|9\.0))", string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 0.19.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
