#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69926);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2013-3466");
  script_bugtraq_id(62028);
  script_osvdb_id(96668);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui57636");
  script_xref(name:"IAVA", value:"2013-A-0167");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130828-acs");

  script_name(english:"Cisco Secure Access Control Server for Windows Remote Code Execution");
  script_summary(english:"Checks version of Cisco Secure ACS for Windows");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an access control application installed
that is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Secure Access Control Server for Windows 4.x is
earlier than 4.2.1.15.11.  It is, therefore, potentially affected by a
remote code execution vulnerability.  Due to improper parsing of user
identities used for EAP-FAST authentication, a remote, unauthenticated
attacker could execute arbitrary code on the remote host subject to the
privileges of the user running the affected application. 

Note that this issue only affects Cisco Secure Access Control Server for
Windows when configured as a RADIUS server.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130828-acs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8f7745e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Secure Access Control Server for Windows 4.2.1.15.11
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_secure_acs_for_windows_installed.nasl");
  script_require_keys("SMB/Cisco Secure ACS for Windows/Path", "SMB/Cisco Secure ACS for Windows/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

kb_base = 'SMB/Cisco Secure ACS for Windows/';
version = get_kb_item_or_exit('SMB/Cisco Secure ACS for Windows/Version');
path = get_kb_item_or_exit('SMB/Cisco Secure ACS for Windows/Path');

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (version =~ '^4\\.' && ver_compare(ver:version, fix:'4.2.1.15.11') < 0)
{
  # Make sure it is configured as a RADIUS server
  nasvendor = NULL;

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key = "SOFTWARE\Cisco";
  subkeys = get_registry_subkeys(handle:hklm, key:key);
  if (!isnull(subkeys))
  {
    foreach subkey (subkeys)
    {
      if (subkey =~ '^CiscoSecure ACS v[0-9\\.]+')
      {
        key = key + '\\' + subkey + "\Setup\NasVendor";
        nasvendor = get_registry_value(handle:hklm, item:key);
        break;
      }
    }
  }
  RegCloseKey(handle:hklm);
  close_registry();

  if (isnull(nasvendor)) exit(1, 'Failed to determine the NAS type.');
  if ('radius' >!< tolower(nasvendor)) exit(0, 'The host is not affected because Cisco Secure ACS for Windows is not configured as a RADIUS server.');

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.2.1.15.11\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Cisco Secure Access Control Server for Windows', version, path);
