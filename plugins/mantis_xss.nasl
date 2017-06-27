#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14344);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2015/01/22 18:36:58 $");

 script_bugtraq_id(9184);
 script_osvdb_id(2934);

 script_name(english:"Mantis < 0.18.1 Multiple Unspecified XSS");
 script_summary(english:"Checks for the version of Mantis");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
cross-site scripting attacks.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of Mantis contains a flaw
in the handling of some types of input.  Because of this, an attacker
may be able to cause arbitrary HTML and script code to be executed in a
user's browser within the security context of the affected website.");
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=202559");
 script_set_attribute(attribute:"solution", value:"Upgrade to Mantis 0.18.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("mantis_detect.nasl");
 script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");


port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(ereg(pattern:"^0\.([0-9]\.|1[0-7]\.|18\.0[^0-9])", string:version))
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 0.18.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
