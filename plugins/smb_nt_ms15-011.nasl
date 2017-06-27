#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81264);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/18 13:48:31 $");

  script_cve_id("CVE-2015-0008");
  script_bugtraq_id(72477);
  script_osvdb_id(118181);
  script_xref(name:"CERT", value:"787252");
  script_xref(name:"MSFT", value:"MS15-011");
  script_xref(name:"IAVA", value:"2015-A-0033");

  script_name(english:"MS15-011: Vulnerability in Group Policy Could Allow Remote Code Execution (3000483)");
  script_summary(english:"Checks the version of gpsvc.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability due to how the Group Policy service manages policy data
when a domain-joined system connects to a domain controller. An
attacker, using a controlled network, can exploit this to gain
complete control of the host.

Note that Microsoft has no plans to release an update for Windows 2003
even though it is affected by this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-011");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-011';
kb = '3000483';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

vuln = FALSE;
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

# Check if the host is joined to a domain
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
res = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\DCName");
if (isnull(res))
{
  close_registry();
  audit(AUDIT_HOST_NOT, 'joined to a domain');
}

# Check if HardenedPaths is enabled
hardenedpaths = 0;
res = get_reg_name_value_table(handle:hklm, key:"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths");
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);
if (!empty_or_null(res) && max_index(keys(res)) > 0)
  hardenedpaths = 1;

if ("2003" >< productname)
{
  info = '
The remote host is running Windows 2003, which is vulnerable to
MS15-011. Microsoft has no plans to release a fix for MS15-011 on
Windows 2003. No workarounds are available.\n';
  hotfix_add_report(info, bulletin:bulletin);
  vuln = TRUE;
}
else if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"gpsvc.dll", version:"6.3.9600.17630", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"gpsvc.dll", version:"6.2.9200.21339", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"gpsvc.dll", version:"6.2.9200.17225", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"gpsvc.dll", version:"6.1.7601.22917", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"gpsvc.dll", version:"6.1.7601.18711", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gpsvc.dll", version:"6.0.6002.23588", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gpsvc.dll", version:"6.0.6002.19279", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  vuln = TRUE;
}

if (vuln)
{
  if ('2003' >!< productname)
  {
    set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
    info =
      '\n  Note that in addition to applying the patch, the GPO setting ' +
      '\n  "Hardened UNC Paths" needs to be enabled.';
    hotfix_add_report(info);
  }
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  if (!hardenedpaths)
  {
    info =
      '\n  KB 3000483 or a related, subsequent update was successfully ' +
      '\n  installed, but the GPO setting "Hardened UNC Paths" has not ' +
      '\n  been enabled.\n';
    hotfix_add_report(info, bulletin:bulletin);
    hotfix_security_hole();
    hotfix_check_fversion_end();
    exit(0);
  }
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
