#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10943);
 script_version("$Revision: 1.58 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id(
   "CVE-2002-0071",
   "CVE-2002-0147",
   "CVE-2002-0149",
   "CVE-2002-0150",
   "CVE-2002-0224",
   "CVE-2002-0869",
   "CVE-2002-1180",
   "CVE-2002-1181",
   "CVE-2002-1182"
 );
 script_bugtraq_id(4006, 4474, 4476, 4478, 4490, 6069, 6070, 6071, 6072);
  script_osvdb_id(
   768,
   771,
   3301,
   3316,
   3320,
   3325,
   3326,
   3328,
   3338,
   3339,
   13434,
   17122,
   17123,
   17124
  );
  script_xref(name:"CERT", value:"610291");
  script_xref(name:"CERT", value:"669779");
  script_xref(name:"CERT", value:"454091");
  script_xref(name:"CERT", value:"721963");
  script_xref(name:"CERT", value:"363715");
  script_xref(name:"CERT", value:"521059");
  script_xref(name:"CERT", value:"412203");
  script_xref(name:"CERT", value:"883091");
  script_xref(name:"CERT", value:"886699");
  script_xref(name:"MSFT", value:"MS02-018");
  script_xref(name:"MSFT", value:"MS02-062");
  script_xref(name:"MSKB", value:"319733");

 script_name(english:"MS02-018: Cumulative Patch for Internet Information Services (327696)");
 script_summary(english:"Determines whether October 30, 2002 IIS Cumulative patches (Q327696) are installed");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
server.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains multiple flaws in the Internet
Information Service (IIS), such as heap overflow, DoS, and XSS that
could allow an attacker to execute arbitrary code on the remote host
with SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-018");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-062");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for IIS 4.0, 5.0, 5.1.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS02-018 Microsoft IIS 4.0 .HTR Path Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/31");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/04/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-018';
kb = '319733';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'1,2', xp:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"W3svc.dll", version:"5.1.2600.1125", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"W3svc.dll", version:"5.0.2195.5995", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"W3svc.dll", version:"4.2.780.1", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb)
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


