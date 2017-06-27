#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71847);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2013-1096");
  script_bugtraq_id(64500);
  script_osvdb_id(100169);

  script_name(english:"Novell Identity Manager Roles Based Provisioning Module taskId XSS");
  script_summary(english:"Checks version of Novell Identity Manager Roles Based Provisioning Module");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Novell Identity Manager Roles Based
Provisioning Module install hosted on the remote web server is affected
by a reflected cross-site scripting vulnerability.  This is due to
improper handling of user input to the 'taskId' parameter in the
'taskDetail.do' script.  By tricking a user into clicking a specially
crafted URL, an attacker may be able to execute arbitrary script code in
a user's web browser in the security context of the affected
application."
  );
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5174070.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0edefee8");
  script_set_attribute(attribute:"solution", value:
"Apply Novell Identity Manager Roles Based Provisioning Module 4.0.2
Field Patch D.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:identity_manager_roles_based_provisioning_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_identity_manager_rbpm_detect.nasl");
  script_require_keys("www/novell_identity_management_rbpm");
  script_require_ports("Services/www", 8180);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8180);

appname_audit = "Novell Identity Manager Role Based Provisioning Module";
appname = "novell_identity_management_rbpm";
base_kb = "www/" + port + "/" + appname + "/";

install = get_install_from_kb(appname:appname, port:port, exit_on_fail:TRUE);
build = get_kb_item_or_exit(base_kb + "build");

dir = install['dir'];
version = install['ver'];
location = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname_audit, location);

# only 4.0.2 affected
if (
  version =~ "^4\.0\.2($|[^0-9])" &&
  build < 41026
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0.2 Patch D' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname_audit, location, version);
