#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73624);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id("CVE-2013-6017", "CVE-2013-6028");
  script_bugtraq_id(64777, 64779);
  script_osvdb_id(101936, 101937);
  script_xref(name:"CERT", value:"204950");

  script_name(english:"Atmail Webmail 6.x / 7.x < 7.2.0 Multiple Vulnerabilities");
  script_summary(english:"Checks Atmail version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Atmail Webmail install on the remote
host is 6.x or 7.x prior to 7.2.0. It is, therefore, potentially
affected by the following vulnerabilities :

  - An input validation error exists related to email
    handling that could allow persistent cross-site
    scripting attacks (XSS). (CVE-2013-6017)

  - An input validation error exists related to
    administration functions that could allow cross-site
    request forgery attacks (XSRF). (CVE-2013-6028)");
  script_set_attribute(attribute:"see_also", value:"https://help.atmail.com/hc/en-us/categories/200214454-Changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade to Atmail Webmail 7.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("atmail_webmail_detect.nasl");
  script_require_keys("www/atmail_webmail");
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

if (version !~ "^[67]\.")
  audit(AUDIT_WEB_APP_NOT_INST, "Atmail Webmail 6.x / 7.x", port);

if (version =~ "^6\." && report_paranoia < 2) audit(AUDIT_PARANOID);

if (ver_compare(ver:version, fix:'7.2.0', strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version + ' ('+display_version+')' +
      '\n  Fixed version     : 7.2.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atmail Webmail", install_url, version);
