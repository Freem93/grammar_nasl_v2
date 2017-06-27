#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73618);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2008-3395", "CVE-2008-3579");
  script_bugtraq_id(30434);
  script_osvdb_id(47271, 47272, 49379);

  script_name(english:"Atmail Webmail < 5.4.2 (5.42) Multiple Information Disclosure Vulnerabilities");
  script_summary(english:"Checks Atmail version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Atmail Webmail install on the remote
host is a version prior to 5.4.2 (5.42). It is, therefore, potentially
affected by the following vulnerabilities :

  - A weak permissions error exists related to the files
    'webmail/libs/Atmail/Config.php' and
    'webmail/webadmin/.htpasswd' that could allow
    disclosure of sensitive information. (CVE-2008-3395)

  - An authentication bypass error exists related to the
    script 'build-plesk-upgrade.php' that could allow
    disclosure of sensitive information. (CVE-2008-3579)");
  script_set_attribute(attribute:"see_also", value:"http://freecode.com/projects/atmail/releases/282536");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/vuln-dev/2008/Jul/1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Atmail Webmail 5.4.2 (5.42) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (ver_compare(ver:version, fix:'5.4.2', strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version + ' ('+display_version+')' +
      '\n  Fixed version     : 5.4.2 (5.42)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atmail Webmail", install_url, version);
