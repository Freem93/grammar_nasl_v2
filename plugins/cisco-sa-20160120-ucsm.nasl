#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88488);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6435");
  script_osvdb_id(133392);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160120-ucsm");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur90888");

  script_name(english:"Cisco Unified Computing System Manager CGI RCE (CSCur90888)");
  script_summary(english:"Checks the UCS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco Unified Computing System (UCS) Manager running on the remote
device is affected by a remote command execution vulnerability due to
unprotected calling of shell commands in the /ucsm/getkvmurl.cgi CGI
script. An unauthenticated, remote attacker can exploit this, via a
crafted HTTP request, to execute arbitrary commands.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160120-ucsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72dbb5d7");
  script_set_attribute(attribute:"solution", value:
"Refer to Cisco bug ID CSCur90888 for any available patches, or contact
the vendor for a fix or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cisco UCS Manager";
get_install_count(app_name:'cisco_ucs_manager', exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:'cisco_ucs_manager', port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = install['version'];

# Oddball version 2.2(2c)A has extra conditions
match = eregmatch(pattern:"^([0-9.]+)(\(([^)]+)\)|$)([A-Z])?", string:version);
if (isnull(match)) audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

major = match[1];
build = "";
if (!empty_or_null(match[3]))
 build = match[3];

# Oddball version 2.2(2c)A has extra conditions
rev = "";
if (!empty_or_null(match[4]))
  rev = match[4];

vuln = FALSE;
if (
  (major == '3.1' && build =~ '1[abcd]T?') ||
  (major == '3.0' && build =~ '(1[a-z]|2[abcd])') ||
  (major == '2.2' && build =~ '(1[a-z]|2[a-z]|3[a-z]|4a)') ||
  (major == '2.2' && build == "" && rev == "") ||
  (major == '2.2' && build == "2c" && rev == "A")
)
{

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See vendor.' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);
