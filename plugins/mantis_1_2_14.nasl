#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(65982);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_cve_id("CVE-2013-1932", "CVE-2013-1934");
  script_bugtraq_id(58891, 58893);
  script_osvdb_id(92023); 

  script_name(english:"MantisBT 1.2.x < 1.2.14 adm_config_report.php Multiple Parameter XSS");
  script_summary(english:"Checks the version of Mantis");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the MantisBT install hosted on the
remote web server is affected by multiple cross-site scripting 
vulnerabilities :

  - A flaw exists in on the Configuration Report page in the
    'adm_config_report.php' script. (CVE-2013-1932)

  - A flaw exists because the application fails to sanitize 
    user input to the 'name' when adding a complex 
    configuration option. This flaw affects MantisBT version
    1.2.13 only. (CVE-2013-1934)

A remote attacker, exploiting these flaws, could execute arbitrary 
script code in a user's browser.");

  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=15415");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=15416");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
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

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 1.2.x < 1.2.14 are vulnerable
if ( ver[0] == 1 && ver[1] == 2 && ver[2] < 14 )
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.2.14\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
