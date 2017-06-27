#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64575);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-1281");
  script_bugtraq_id(57853);
  script_osvdb_id(90129);
  script_xref(name:"MSFT", value:"MS13-014");
  script_xref(name:"IAVB", value:"2013-B-0013");

  script_name(english:"MS13-014: Vulnerability in NFS Server Could Allow Denial of Service (2790978)");
  script_summary(english:"Checks version of NfsSvr.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is potentially affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is potentially affected by a vulnerability that
could allow denial of service if an attacker attempts a file operation
on a read-only share.  An attacker who exploited this vulnerability
could cause the affected system to stop responding and restart.  The
vulnerability only affects Windows servers with the NFS role enabled."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-014");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for 2008 R2 and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");


get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-014';
kb = '2790978';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# This issue only affects 2008 R2 and 2012
if (hotfix_check_sp_range(win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# This issue does not affect Windows 7 or 8
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Embedded" >< productname || "Windows 7" >< productname || "Windows 8" >< productname) exit(0, "The host is running "+productname+" and is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Check to see if the NFS role is enabled
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
path = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Services\NfsServer\ImagePath");
RegCloseKey(handle:hklm);
close_registry();

if (isnull(path)) exit(0, 'The NFS role is not enabled on the remote host.');


if (
  # 2008 R2 x64 SP 0,1
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"NfsSvr.sys", version:"6.1.7600.17204",   min_version:"6.1.7600.16000",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"NfsSvr.sys", version:"6.1.7600.21414",   min_version:"6.1.7600.20000",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"NfsSvr.sys", version:"6.1.7601.18041",   min_version:"6.1.7601.17000",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"NfsSvr.sys", version:"6.1.7601.22207",   min_version:"6.1.7601.21000",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # 2012
  hotfix_is_vulnerable(os:"6.2",             sp:0, file:"NfsSvr.sys", version:"6.2.9200.16490",   min_version:"6.2.9200.16000",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2",             sp:0, file:"NfsSvr.sys", version:"6.2.9200.20595",   min_version:"6.2.9200.20000",     dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
