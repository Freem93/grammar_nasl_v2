#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84735);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-2374");
  script_bugtraq_id(75633);
  script_osvdb_id(124596);
  script_xref(name:"MSFT", value:"MS15-071");
  script_xref(name:"IAVA", value:"2015-A-0173");

  script_name(english:"MS15-071: Vulnerability in NETLOGON Could Allow Elevation of Privilege (3068457)");
  script_summary(english:"Checks the version of Netlogon.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability due to the Netlogon service improperly establishing a
communications channel to a primary domain controller (PDC). An
attacker, with access to the PDC, can exploit this by using a crafted
application to create a secure channel to the PDC as a backup domain
controller (BDC), possibly allowing access to sensitive credential
information.

Note that this vulnerability only affects a server if it is configured
as a domain controller.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-071");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, 2008, 2008
R2, 2012, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-071';
kb  = "3068457";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Server" >!< productname) audit(AUDIT_OS_SP_NOT_VULN); # non-server OSes are not affected

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Unless paranoid, check if the server is a DC
if (report_paranoia < 2)
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  res = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType");
  RegCloseKey(handle:hklm);
  if (res != 'LanmanNT')
  {
    close_registry();
    audit(AUDIT_HOST_NOT, 'configured as a domain controller');
  }

  NetUseDel(close:FALSE);
}

if (
  # Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"netlogon.dll", version:"6.3.9600.17901", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"netlogon.dll", version:"6.2.9200.21506", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"netlogon.dll", version:"6.2.9200.17395", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"netlogon.dll", version:"6.1.7601.23083", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"netlogon.dll", version:"6.1.7601.18880", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netlogon.dll", version:"6.0.6002.23716", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netlogon.dll", version:"6.0.6002.19409", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"netlogon.dll", version:"5.2.3790.5648", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
