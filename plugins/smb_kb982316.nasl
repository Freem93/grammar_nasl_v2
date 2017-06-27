#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(48761);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_cve_id("CVE-2010-1886");
  script_bugtraq_id(42278);
  script_osvdb_id(67083);

  script_name(english:"MS KB982316: Elevation of Privilege Using Windows Service Isolation Bypass");
  script_summary(english:"Checks version of tapisrv.dll");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"Windows Service Isolation can be bypassed on the remote host,
resulting in the elevation of privileges.

A local attacker could exploit this by leveraging the TAPI service to
execute code as SYSTEM.

A similar problem affects other Windows services that run as the
NetworkService user (e.g. IIS, SQL Server), though Nessus has not
checked for those issues.");
  script_set_attribute(attribute:"see_also", value:"http://argeniss.com/research/TokenKidnappingRevengePaper.pdf");
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/advisory/2264072"
  );
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2 :

http://technet.microsoft.com/en-us/security/advisory/2264072

Although these patches mitigate this vulnerability, users should be
aware this is considered a non-security update by Microsoft. Refer to
the Microsoft advisory for more information.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

ACCESS_ALLOWED_ACE_TYPE = 0;

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:1) <= 0)
  exit(0, 'The host is not affected based on its version / service pack.');

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

key = "Software\Microsoft\Windows\CurrentVersion\Telephony";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (isnull(key_h))
{
  NetUseDel();
  exit(1, "Can't access the 'HKLM\"+key+"' registry key.");
}

sd = RegGetKeySecurity(handle:key_h, type:DACL_SECURITY_INFORMATION);
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

if (isnull(sd)) exit(1, "Can't  access the security descriptor for the 'HKLM\"+ key + "' registry key.");

dacl = sd[3];
dacl = parse_pdacl(blob:dacl);
if (isnull(dacl)) exit(1, "Error parsing DACL.");

vulnerable = FALSE;

foreach ace (dacl)
{
  ace = parse_dacl(blob:ace);
  if (isnull(ace))
  {
    debug_print("Error parsing ACE.");
    continue;
  }

  rights = ace[0];
  type = ace[3];
  sid = sid2string(sid:ace[1]);
  if (isnull(sid))
  {
    debug_print(1, "Error parsing SID.");
    continue;
  }

  # Check if this is 1) an allow ACE 2) for Network Service 3) that allows full control
  if (
    type == ACCESS_ALLOWED_ACE_TYPE &&
    sid == '1-5-20' &&
    rights & KEY_ALL_ACCESS == KEY_ALL_ACCESS
  )
  {
    vulnerable = TRUE;
    break;
  }
}

if (vulnerable)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\nThe Network Service group has Full Control rights to :\n\n'+
      '  HKLM\\'+key+'\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
  # never reached
  # Exit on the first sign that the system is unpatched
}

# I ran into one circumstance where the registry looked fine on unpatched
# systems.  In these cases, the plugin should check to see if tapisrv.dll
# has been updated, just to be safe.
if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"Tapisrv.dll", version:"6.1.7600.20756", min_version:"6.1.7600.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", file:"Tapisrv.dll", version:"6.1.7600.16637", min_version:"6.1.7600.16000", dir:"\system32") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Tapisrv.dll", version:"6.0.6002.22390", min_version:"6.0.6002.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Tapisrv.dll", version:"6.0.6002.18247", min_version:"6.0.6002.18000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Tapisrv.dll", version:"6.0.6001.22676", min_version:"6.0.6001.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Tapisrv.dll", version:"6.0.6001.18463", min_version:"6.0.6001.18000", dir:"\system32") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Tapisrv.dll", version:"5.2.3790.4699", dir:"\system32")

  # After patching, I didn't see tapicust.dll on XP 32-bit so I'll omit the file version check here.
  # The patch _should_ be detected by the registry check above, though
)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
