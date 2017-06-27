#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85334);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/16 13:18:37 $");

  script_cve_id("CVE-2015-2423");
  script_bugtraq_id(76202);
  script_osvdb_id(125961);
  script_xref(name:"MSFT", value:"MS15-088");
  script_xref(name:"IAVA", value:"2015-A-0197");

  script_name(english:"MS15-088: Unsafe Command Line Parameter Passing Could Allow Information Disclosure (3082458)");
  script_summary(english:"Checks the version of notepad.exe and shell32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an information disclosure
vulnerability when files at a medium integrity level become accessible
to Internet Explorer running in Enhanced Protection Mode (EPM). An
attacker can exploit this vulnerability by leveraging another
vulnerability to execute code in IE with EPM, and then executing
Excel, Notepad, PowerPoint, Visio, or Word using an unsafe command
line parameter.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-088");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_nt_ms15-079.nasl", "smb_nt_ms15-081.nasl");
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

bulletin       = 'MS15-088';
vuln           = 0;

kbs = make_list("3046017", "3079757", "3081436");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

#
# KB 3046017 (notepad.exe)
#
# Affects :
# Windows Server 2012 R2 Datacenter
# Windows Server 2012 R2 Standard
# Windows Server 2012 R2 Essentials
# Windows Server 2012 R2 Foundation
# Windows 8.1 Enterprise
# Windows 8.1 Pro
# Windows 8.1
# Windows RT 8.1
# Windows Server 2012 Datacenter
# Windows Server 2012 Standard
# Windows Server 2012 Essentials
# Windows Server 2012 Foundation
# Windows 8 Enterprise
# Windows 8 Pro
# Windows 8
# Windows RT
# Windows Server 2008 R2 Service Pack 1
# Windows 7 Service Pack 1
# Windows Server 2008 Service Pack 2
# Windows Vista Service Pack 2
if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"notepad.exe", version:"6.3.9600.17930", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3046017") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"notepad.exe", version:"6.2.9200.21545", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3046017") ||
  hotfix_is_vulnerable(os:"6.2", file:"notepad.exe", version:"6.2.9200.17434", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3046017") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"notepad.exe", version:"6.1.7601.23120", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3046017") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"notepad.exe", version:"6.1.7601.18917", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3046017") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"notepad.exe", version:"6.0.6002.23746", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3046017") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"notepad.exe", version:"6.0.6002.19438", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3046017")
) vuln++;

#
# KB3079757 (Shell32.dll)
# https://support.microsoft.com/en-us/kb/3079757
#
# Affects :
# Windows Server 2008 R2 Service Pack 1
# Windows 7 Service Pack 1
# Windows Server 2008 Service Pack 2
# Windows Vista Service Pack 2
#
if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"shell32.dll", version:"6.1.7601.23121", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3079757") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"shell32.dll", version:"6.1.7601.18918", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3079757") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.23748", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3079757") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.19440", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3079757")
) vuln++;

#
# KB3081436 (notepad.exe and shell32.dll)
#
# Affects :
# Windows 10
#
if (
  hotfix_is_vulnerable(os:"10", sp:0, file:"notepad.exe", version:"10.0.10240.16425", min_version:"10.0.10240.1600", dir:"\system32", bulletin:bulletin, kb:"3081436") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"shell32.dll", version:"10.0.10240.16425", min_version:"10.0.10240.1600", dir:"\system32", bulletin:bulletin, kb:"3081436")
) vuln++;

# Must have MS15-079 (IE) as well to be protected
if (
  !vuln
  &&
  get_kb_item("SMB/MS15-079/Missing")
)
{
  vuln++;
  hotfix_add_report("Note that the remote system is still vulnerable because the requisite patch for MS15-079 is missing.");
}

# If Office is installed, must have MS15-081 as well to be protected
if (
  !vuln
  &&
  get_kb_list("SMB/Office/*")
  &&
  get_kb_item("SMB/MS15-081/Missing")
)
{
  vuln++;
  hotfix_add_report("Note that the remote system is still vulnerable because the requisite patch for MS15-081 is missing.");
}

if (vuln)
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
