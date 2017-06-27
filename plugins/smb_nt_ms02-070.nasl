#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11215);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-1256");
 script_bugtraq_id(6367);
 script_osvdb_id(11799);
 script_xref(name:"MSFT", value:"MS02-070");
 script_xref(name:"MSKB", value:"329170");

 script_name(english:"MS02-070: Flaw in SMB Signing Could Enable Group Policy to be Modified (329170)");
 script_summary(english:"Checks for MS Hotfix 329170");

 script_set_attribute(attribute:"synopsis", value:"It is possible to send unsigned SMB packets.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the SMB signing
implementation.  SMB signing is used to sign each packets sent between a
client and a server to protect them against man-in-the-middle attacks.

If the Domain policy is configured to force usage of SMB signing, it is
possible for an attacker to downgrade the communication to disable SMB
signing and try to launch man-in-the-middle attacks.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-070");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2000.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/25");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-070';
kb = '329170';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'2,3', xp:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1154", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Srv.sys", version:"5.1.2600.105", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Srv.sys", version:"5.0.2195.6110", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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


