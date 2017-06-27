#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58816);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_cve_id("CVE-2012-0740");
  script_bugtraq_id(52844);
  script_osvdb_id(80871);

  script_name(english:"IBM Tivoli Directory Server Web Administration Tool Unspecified XSS");
  script_summary(english:"Checks version of Tivoli Directory Server Web Administration Tool");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the IBM Tivoli Directory Server Web
Administration Tool installed on the remote host is potentially
affected by an unspecified cross-site scripting vulnerability. 

A remote attacker, exploiting this flaw, could potentially execute
arbitrary script code in the user's browser in the security context of
the affected site.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_tivoli_directory_server_cross_site_scripting_vulnerability_with_the_web_admin_tool_cve_2012_07404?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?840acc71");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21591257");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24032501");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24032291");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24032290");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Directory Server 6.1.0.48 (Web Admin version 
4.0027), 6.2.0.22 (Web Admin version 5.0015), 6.3.0.11 (Web Admin 
version 6.0006) or later. 

After upgrading Tivoli Directory Server, you must redeploy the web
application through WebSphere.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_directory_srv_web_admin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/tivoli_directory_server_web_admin_tool");
  script_require_ports("Services/www", 9080, 12100);

  exit(0); 
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:12100);

install = get_install_from_kb(appname:'tivoli_directory_server_web_admin_tool', port:port, exit_on_fail:TRUE);

version = install['ver'];
url = build_url(port:port, qs:install['dir']);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Tivoli Directory Server Web Administration Tool', url);

fix = NULL;
if (version =~ '4\\.' && ver_compare(ver:version, fix:'4.0027') < 0) fix = '4.0027';
else if (version =~ '5\\.' && ver_compare(ver:version, fix:'5.0015') < 0) fix = '5.0015';
else if (version =~ '6\\.' && ver_compare(ver:version, fix:'6.0006') < 0) fix = '6.0006';

if (fix)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL                               : ' + url +
      '\n  Installed web application version : ' + version +
      '\n  Fixed web application version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Tivoli Directory Server Web Administration Tool', url, version);
