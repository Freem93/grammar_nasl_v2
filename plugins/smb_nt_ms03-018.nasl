#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11683);
 script_version("$Revision: 1.40 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id(
   "CVE-2003-0223",
   "CVE-2003-0224",
   "CVE-2003-0225",
   "CVE-2003-0226"
 );
 script_bugtraq_id(7731, 7733, 7734, 7735);
 script_osvdb_id(13385, 4655, 4863, 7737);
 script_xref(name:"MSFT", value:"MS03-018");
 script_xref(name:"MSKB", value:"811114");

 script_name(english:"MS03-018: Cumulative Patch for Internet Information Services (11114)");
 script_summary(english:"Determines if HF Q811114 has been installed");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote web server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of IIS that contains various flaws
that could allow remote attackers to disable this service remotely and
local attackers (or remote attackers with the ability to upload
arbitrary files on this server) to gain SYSTEM level access on this
host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-018");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for IIS 4.0, 5.0 and 5.1.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/05/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/02");

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

bulletin = 'MS03-018';
kb = "811114";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'2,3', xp:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", file:"W3svc.dll", version:"5.1.2600.1166", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"W3svc.dll", version:"5.0.2195.6672", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"W3svc.dll", version:"4.2.785.1",     dir:"\system32\inetsrv", bulletin:bulletin, kb:kb)
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
