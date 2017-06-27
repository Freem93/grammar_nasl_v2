#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38650);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:21:29 $");

  script_cve_id("CVE-2009-2455");
  script_bugtraq_id(34762);
  script_osvdb_id(54126);
  script_xref(name:"Secunia", value:"34403");

  script_name(english:"Atmail WebMail <= 5.6.1 (5.61) webadmin/admin.php Multiple Parameter XSS");
  script_summary(english:"Checks the version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application with multiple cross-site
scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Atmail WebMail running on the remote host is vulnerable
to multiple cross-site scripting issues. 'webadmin/admin.php' fails to
sanitize input to the 'func' parameter, and to the 'type' parameter
(when 'func' is set to 'stats'). This is known to affect version 5.6.1
(5.61) and may affect previous versions as well.

A remote attacker could exploit this by tricking a user into
requesting a web page with arbitrary script code injected. This could
lead to consequences such as stolen authentication credentials.");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("atmail_webmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'atmail_webmail', port:port, exit_on_fail:TRUE);

dir = install['dir'];
display_version = install['ver'];
# Get normalized version for check
kb_dir = str_replace(string:dir, find:"/", replace:"\");
version = get_kb_item_or_exit('www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+display_version);
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER || isnull(version))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "Atmail Webmail", install_url);

if (ver_compare(ver:version, fix:'5.6.1', strict:FALSE) <= 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
    url = string(dir, "/webadmin/admin.php?func=", xss);

        report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version + ' ('+display_version+')\n\n';

    report += "
Nessus was only able to detect this issue by looking at the
application's version number. Please confirm this issue exists by
attempting a non-persisent XSS attack using the following URL :

  " + build_url(port:port, qs:url) +
'\n\nNote that this URL requires authentication.\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atmail Webmail", install_url, version);
