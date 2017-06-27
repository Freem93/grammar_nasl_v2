#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70855);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/11 15:54:32 $");

  script_cve_id("CVE-2013-3876");
  script_bugtraq_id(63666);
  script_osvdb_id(99692);

  script_name(english:"MS KB2862152: Vulnerability in DirectAccess Could Allow Security Feature Bypass");
  script_summary(english:"Checks for Ikeext.dll / Oakley.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a security feature vulnerability due to
improper verification of server X.509 certificates by DirectAccess.
A man-in-the-middle attacker, by using a server with a crafted
certificate installed, can exploit this flaw to pose as a legitimate
server to a targeted client, thus allowing interception of the
target's network traffic and domain credentials.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2862152");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, 2012, 8.1 and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

product = get_kb_item_or_exit("SMB/ProductName");
winver = get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, 'Failed to get the system root.');

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# First check if the host is configured to use DirectAccess
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "Software\Policies\Microsoft\Windows NT\DNSClient\EnableDirectAccessForAllNetworks";
ret = get_registry_value(handle:hklm, item:key);
if (isnull(ret))
{
  key = "System\CurrentControlSet\services\Dnscache\Parameters\EnableDirectAccessForAllNetworks";
  ret = get_registry_value(handle:hklm, item:key);
  if (isnull(ret))
  {
    key = "SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\DirectAccess-VPN\InstallState";
    ret = get_registry_value(handle:hklm, item:key);
  }
}
if (isnull(ret) || (int(ret) != 1 && int(ret) != 2))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0, 'The host is not affected because it does not appear to be using DirectAccess.');
}

# While the registry is open, check for the keys needed to
# enforce the update for Windows 8/8.1 only.
configured = FALSE;
if ('6.2' >< winver || '6.3' >< winver)
{
  key = "SYSTEM\CurrentControlSet\Services\IKEEXT\Parameters\IPsecTunnelConfig\AuthIP\kerberos";
  kerb = get_registry_value(handle:hklm, item:key);
  if (!isnull(kerb) || "Windows 8" >!< product)
  {
    configured = TRUE;
  }
}
if ('6.0' >< winver || '6.1' >< winver)
{
  keys = make_list('SYSTEM\\CurrentControlSet\\Services\\IKEEXT\\Parameters\\IPsecTunnelConfig\\AuthIP',
                   'SYSTEM\\CurrentControlSet\\Services\\IKEEXT\\Parameters\\IPSecTunnelConfig\\IKEV1');
  for (i=0; i < max_index(keys); i++)
  {
    subkeys = get_registry_subkeys(handle:hklm, key:key);
    if (!isnull(subkeys))
    {
      for (j=0; j < max_index(subkeys); j++)
      {
        if (tolower(subkeys[j])  =~ '^cert$')
        {
          configured = TRUE;
          break;
        }
      }
    }
  }
}
else if ('5.1' >< winver || '5.2' >< winver)
{
  key = 'SYSTEM\\CurrentControlSet\\Services\\PolicyAgent\\Oakley';
  subkeys = get_registry_subkeys(handle:hklm, key:key);
  if (!isnull(subkeys))
  {
    for (i=0; i < max_index(subkeys); i++)
    {
      if (tolower(subkeys[i]) =~ '^cert$')
      {
        configured = TRUE;
        break;
      }
    }
  }
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (
  # Windows 8.1 and Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Ikeext.dll", version:"6.3.9600.16427", min_version:"6.3.9600.16000", dir:"\system32") ||

  # Windows 8 and Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ikeext.dll", version:"6.2.9200.20846", min_version:"6.2.9200.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ikeext.dll", version:"6.2.9200.16734", min_version:"6.2.9200.16000", dir:"\system32") ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ikeext.dll", version:"6.1.7601.22479", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ikeext.dll", version:"6.1.7601.18283", min_version:"6.1.7600.17000", dir:"\system32") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ikeext.dll", version:"6.0.6002.23243", min_version:"6.0.6002.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ikeext.dll", version:"6.0.6002.18960", min_version:"6.0.6002.18000", dir:"\system32") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Oakley.dll", version:"5.2.3790.5238", dir:"\system32") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Oakley.dll", version:"5.1.2600.6462", dir:"\system32")
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
}

  # If the patch is installed, make sure the appropriate registry keys are set
if (!configured)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  The remote host is missing the required registry configurations to' +
      '\n  enforce validation. Refer to the Microsoft advisory for more' +
      '\n  information.';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

audit(AUDIT_HOST_NOT, 'affected');
