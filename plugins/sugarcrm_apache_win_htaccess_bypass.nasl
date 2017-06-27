#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42962);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_bugtraq_id(37136);
  script_osvdb_id(60510);
  script_xref(name:"Secunia", value:"37464");

  script_name(english:"SugarCRM on Apache / Windows .htaccess Direct Request Arbitrary File Access");
  script_summary(english:"Tries to retrieve install.log");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SugarCRM running on the remote host has an information
disclosure vulnerability. When Apache is running on Windows, .htaccess
restrictions are case-sensitive, but filenames are not. A remote
attacker can bypass .htaccess restrictions by using uppercase letters
when requesting files that should be restricted. The information
gathered from restricted files could be used to mount further attacks.

There are reportedly other vulnerabilities in this version of
SugarCRM, though Nessus has not checked for those issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-76.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6d5d1d8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SugarCRM 5.2.0k / 5.5.0.RC4 or later.

If SugarCRM is running on Apache 1.3.x (which is still affected by
this issue), use the referenced vendor workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("sugarcrm_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/sugarcrm");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


# This only affects Apache on Windows.  Only proceed if the OS looks right
# (or it couldn't be detected)
os = get_kb_item("Host/OS");
if (!isnull(os) && 'Windows' >!< os)
  exit(0, "The remote host does not appear to be running Windows.");

port = get_http_port(default:80);

# Then check the banner, unless we're paranoid
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!isnull(banner) && 'Apache' >!< banner)
    exit(0, 'The web server on port '+port+' does not look like Apache.');
}

install = get_install_from_kb(appname:'sugarcrm', port:port);
if (isnull(install))
  exit(1, "The 'www/"+port+"/sugarcrm' KB item is missing.");

url = install['dir'] + '/install.Log';
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (
  'Begin System Check Process' >< res[2] &&
  'Installation has completed' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  sugar_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The SugarCRM install at " + sugar_url + " is not affected.");
}
