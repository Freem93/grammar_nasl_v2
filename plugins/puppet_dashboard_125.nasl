#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73823);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2012-0891");
  script_bugtraq_id(66602);
  script_osvdb_id(84561);

  script_name(english:"Puppet Dashboard Multiple XSS Vulnerabilities");
  script_summary(english:"Checks Puppet Dashboard version");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is potentially affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Dashboard
install on the remote host is later than version 1.0 but prior to
1.2.5. It is, therefore, affected by multiple cross-site scripting
vulnerabilities.

Multiple cross-site scripting flaws exist where unspecified input is
not validated before being returned to the user. This could allow a
remote attacker to execute arbitrary code within the browser and
server trust relationship.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2012-0891");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Dashboard 1.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet_dashboard");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 3000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:3000);

# Puppet Dashboard is Open Source
if (report_paranoia < 2) audit(AUDIT_PARANOID);

url = '/';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
if ('<li class=\'\' id=\'dashboard-version\'>' >!< res[2]) audit(AUDIT_WEB_APP_NOT_INST, 'Puppet Dashboard', port);


regex = '<a href=".*puppetlabs.*">(PE [0-9.]+|[0-9.rc]+)</a>';
matches = eregmatch(string:res[2], pattern:regex);
if (isnull(matches)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, 'Puppet Dashboard', port);
version = matches[1];

dir = '';
install = add_install(appname:'puppet_dashboard', dir:dir, ver:version, port:port);
install_url = build_url(port:port, qs:install["dir"]);

if (version =~ "^PE") exit(0, "Puppet Enterprise Dashboard installed at "+ install_url);

if (
  version =~ "^1\.[01]([^0-9]|$)" ||
  version =~ "^1\.2\.[0-4]([^0-9]|$)"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.2.5' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Puppet Dashboard", install_url, version);
