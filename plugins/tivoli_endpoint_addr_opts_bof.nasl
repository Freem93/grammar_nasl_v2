#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54924);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2011-1220");
  script_bugtraq_id(48049);
  script_osvdb_id(72713);
  script_xref(name:"TRA", value:"TRA-2011-04");
  script_xref(name:"IAVA", value:"2011-A-0072");
  script_xref(name:"EDB-ID", value:"17365");
  script_xref(name:"EDB-ID", value:"17392");

  script_name(english:"IBM Tivoli Management Framework Endpoint addr URL Remote Buffer Overflow");
  script_summary(english:"Does a version check on TMF Endpoint");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web server running on the remote host has a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the Tivoli Endpoint
installation running on the remote host is earlier than 4.1.1-LCF-0076
or 4.3.1-LCF-0012LA, and therefore has a buffer overflow
vulnerability.  Input to the 'opts' parameter of '/addr' is not
properly validated.  Authentication is required for exploitation,
though this can be achieved trivially by using a built-in account.

A remote, authenticated attacker could exploit this by sending a
malicious POST request to the server, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-04");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-169/");
  script_set_attribute(attribute:"see_also",value:"https://www-304.ibm.com/support/docview.wss?uid=swg21499146");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Tivoli Endpoint 4.1.1-LCF-0076 / 4.3.1-LCF-0012LA
or later.  Alternatively, use the workaround described in the
IBM advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Tivoli Endpoint Manager POST Query Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_management_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("tivoli_endpoint_detect.nasl");
  script_require_keys("www/tivoli_endpoint");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9495, embedded:TRUE);
install = get_install_from_kb(appname:'tivoli_endpoint', port:port, exit_on_fail:TRUE);
ver = install['ver'];
if (ver == UNKNOWN_VER) exit(1, 'Unable to determine version on port '+port+'.');

match = eregmatch(string:ver, pattern:'^([0-9]+)');
if (!match) exit(1, 'Error parsing the version of Tivoli Management Framework Endpoint listening on port '+port+' (' + ver + ').');
else build = int(match[1]);

# do the version check
fix = NULL;
if (build < 41176)
  fix = '41176 (4.1.1-LCF-0076)';
else if (build >= 43100 && build < 43112)
  fix = '43112 (4.3.1-LCF-0012LA)';
else
  exit(0, 'Tivoli Management Framework Endpoint version '+ver+' is listening on port '+port+' and thus not affected.');

# make sure the workaround isn't in use unless paranoid
info = NULL;
if (report_paranoia < 2)
{
  # if the workaround is applied (disable configuration via HTTP), there will be an
  # error message saying so. if there's no workaround, we'll be prompted for auth
  res = http_send_recv3(method:'POST', port:port, item:'/addr', exit_on_fail:TRUE);

  if ('Configuration capability has been disabled on this endpoint' >< res[2])
    exit(0, 'The workaround has been applied on port ' + port + '.');
}
else
{
  info =
    '\nNessus did not check if the workaround is in use since' +
    '\nReport Paranoia is set to "Paranoid".\n';
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n' +
    info;
  security_hole(port:port, extra:report);
}
else security_hole(port);
