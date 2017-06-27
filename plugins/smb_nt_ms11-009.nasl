#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51909);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/09/26 19:18:37 $");

  script_cve_id("CVE-2011-0031");
  script_bugtraq_id(46139);
  script_osvdb_id(70827);
  script_xref(name:"MSFT", value:"MS11-009");

  script_name(english:"MS11-009: Vulnerability in JScript and VBScript Scripting Engine Could Allow Information Disclosure (2475792)");
  script_summary(english:"Checks version of Vbscript.dll and JScript.dll");

  script_set_attribute(attribute:"synopsis", value:
"An information disclosure vulnerability exists in the JScript and
VBscript engines.");
  script_set_attribute(attribute:"description", value:
"The installed versions of the VBScript and JScript Scripting Engines
allow an attacker to obtain sensitive information by enticing a user
into visiting a specially crafted website.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-009");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-009';
kb = "2475792";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if (hotfix_check_ie_version() =~ "^9\.") audit(AUDIT_INST_VER_NOT_VULN, 'IE', '9');

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  # Windows 7 and Windows Server 2008 R2 - KB2475792
  # JScript
  hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll", version:"5.8.7601.21634", min_version:"5.8.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll", version:"5.8.7601.17535", min_version:"5.8.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll", version:"5.8.7600.20873", min_version:"5.8.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll", version:"5.8.7600.16732", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # VBScript
  hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7601.21634", min_version:"5.8.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7601.17535", min_version:"5.8.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7600.20873", min_version:"5.8.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7600.16732", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb)
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
