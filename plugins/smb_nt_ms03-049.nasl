#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11921);
 script_version("$Revision: 1.55 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0812");
 script_bugtraq_id(9011);
 script_osvdb_id(11461);
 script_xref(name:"CERT-CC", value:"CA-2003-28");
 script_xref(name:"MSFT", value:"MS03-049");
 script_xref(name:"CERT", value:"567620");
 script_xref(name:"MSKB", value:"828035");
 script_xref(name:"MSKB", value:"828749");

 script_name(english:"MS03-049: Buffer Overflow in the Workstation Service (828749)");
 script_summary(english:"Checks for hotfix 828749");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the function
NetpValidateName() in the WorkStation service that could allow an
attacker to execute arbitrary code on the remote host with the SYSTEM
privileges.

A series of worms (Welchia, Spybot, ...) are known to exploit this
vulnerability in the wild.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-049");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS03-049 Microsoft Workstation Service NetAddAlternateComputerName Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/11/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/11/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS03-049';
kbs = make_list("828035", "828749");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'2,4', xp:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Msasn1.dll", version:"5.1.2600.1309", dir:"\system32", bulletin:bulletin, kb:'828035') ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Msasn1.dll", version:"5.1.2600.121", dir:"\system32", bulletin:bulletin, kb:'828035') ||

  hotfix_is_vulnerable(os:"5.0", file:"wkssvc.dll", version:"5.0.2195.6862", dir:"\system32", bulletin:bulletin, kb:'828749')
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
