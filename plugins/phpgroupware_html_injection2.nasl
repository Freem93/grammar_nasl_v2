#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16138);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2004-2574");
  script_bugtraq_id(12082);
  script_osvdb_id(7599, 7600, 7601, 7602, 7603, 7604);

  script_name(english:"phpGroupWare index.php Calendar Date XSS");
  script_summary(english:"Checks for PhpGroupWare version");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PhpGroupWare on the remote host is reportedly affected
by HTML injection vulnerabilities that present themselves due to a
lack of sufficient input validation performed on form fields used by
PhpGroupWare modules.

A malicious attacker may exploit these issues to inject arbitrary HTML
and script code using these form fields that then may be incorporated
into dynamically-generated web content.");
  script_set_attribute(attribute:"see_also", value:"https://savannah.gnu.org/bugs/?func=detailitem&item_id=7478");
  script_set_attribute(attribute:"solution", value:"Update to version 0.9.16 RC3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgroupware:phpgroupware");
  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_dependencies("phpgroupware_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/phpGroupWare");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpGroupWare", port:port, exit_on_fail:TRUE);
dir = install['dir'];

url = dir + "/phpsysinfo/inc/hook_admin.inc.php";
res = http_send_recv3(method: "GET", item:url, port:port, exit_on_fail:TRUE);

if (egrep(pattern:".*Fatal error.* in <b>/.*", string:res[2]))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpGroupWare", build_url(qs:dir, port:port));
