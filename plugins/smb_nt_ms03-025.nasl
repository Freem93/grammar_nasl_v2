#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11789);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0350");
 script_bugtraq_id(8154);
 script_osvdb_id(13410);
 script_xref(name:"MSFT", value:"MS03-025");
 script_xref(name:"MSKB", value:"822679");

 script_name(english:"MS03-025: Flaw in Windows Message Handling through Utility Manager Could Enable Privilege Elevation (822679)");
 script_summary(english:"Checks for hotfix Q822679");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges.");
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows that has a flaw in the way
the utility manager handles Windows messages.  As a result, it is
possible for a local user to gain additional privileges on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-025");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/07/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/13");

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

bulletin = 'MS03-025';
kb = "822679";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'2,3') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(os:"5.0", file:"Umandlg.dll", version:"1.0.0.3", dir:"\system32", bulletin:bulletin, kb:kb))
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
