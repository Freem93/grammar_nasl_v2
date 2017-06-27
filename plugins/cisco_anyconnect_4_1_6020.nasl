#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86302);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2015-6305");
  script_osvdb_id(127894);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv01279");
  script_xref(name:"EDB-ID", value:"38289");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 3.x < 3.1.11004.0 / 4.x < 4.1.6020.0 Privilege Escalation");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco AnyConnect Secure Mobility Client installed on the remote
host is version 3.x prior to 3.1.11004.0 or 4.x prior to 4.1.6020.0.
It is, therefore, affected by an untrusted search path flaw in the
CMainThread::launchDownloader method due to a failure to check the
path to the downloader application and associated DLL files. An
authenticated, local attacker can exploit this, via running the
downloader application from outside its expected location and
providing crafted DLLs, to execute arbitrary commands on the host with
privileges equivalent to the SYSTEM account.

Note that this vulnerability resulted from an incomplete fix for
CVE-2015-4211.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=41136");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv01279");
  # https://www.securify.nl/advisory/SFY20150601/cisco_anyconnect_elevation_of_privileges_via_dll_side_loading.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d12c6fa4");
  # https://code.google.com/p/google-security-research/issues/detail?id=460
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?714e1c2a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version
3.1.11004.0 / 4.1.6020.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

if (ver =~ "^4\." && (ver_compare(ver:ver, fix:'4.1.6020.0', strict:FALSE) < 0))
  fix = '4.1.6020.0';
else if (ver =~ "^3\." && ver_compare(ver:ver, fix:'3.1.11004.0', strict:FALSE) < 0)
  fix = '3.1.11004.0';
else if (ver =~ "^2\.")
  fix = '3.1.11004.0';
else
  fix = NULL;

if (!isnull(fix))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);
