#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(29307);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2007-5351");
 script_bugtraq_id(26777);
 script_osvdb_id(39125);
 script_xref(name:"MSFT", value:"MS07-063");
 script_xref(name:"IAVT", value:"2007-T-0049");
 script_xref(name:"CERT", value:"520465");

 script_name(english:"MS07-063: Vulnerability in SMBv2 Could Allow Remote Code Execution (942624)");
 script_summary(english:"Determines the presence of update 942624");

 script_set_attribute(attribute:"synopsis", value:"It is possible to execute code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of SMBv2 (Server
Message Block) protocol that has several vulnerabilities.

An attacker may exploit these flaws to elevate his privileges and gain
control of the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-063");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-063';
kb = '942624';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mrxsmb.sys", version:"6.0.6000.16586", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mrxsmb.sys", version:"6.0.6000.20709", min_version:"6.0.6000.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
