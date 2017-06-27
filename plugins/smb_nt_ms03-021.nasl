#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11774);
 script_version("$Revision: 1.43 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0348");
 script_bugtraq_id(8034);
 script_osvdb_id(10997);
 script_xref(name:"MSFT", value:"MS03-021");
 script_xref(name:"CERT", value:"320516");
 script_xref(name:"MSKB", value:"819639");

 script_name(english:"MS03-021: Windows Media Player Library Access (819639)");
 script_summary(english:"Checks the version of Media Player");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the media
player.");
 script_set_attribute(attribute:"description", value:
"An ActiveX control included with Windows Media Player 9 Series may
allow a rogue website to gain information about the remote host.

An attacker could exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player.

To exploit this flaw, an attacker would need to set up a rogue website
and lure a user of this host into visiting it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-021");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for WMP 6.4, 7.1 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/06/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/26");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_player");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms05-009.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_exclude_keys("SMB/Win2003/ServicePack");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS03-021';
kb = "819639";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/WindowsVersion');
get_kb_item_or_exit("SMB/registry_full_access");

if (hotfix_check_sp(win2k:5, xp:1, win2003:1) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (get_kb_item("SMB/890261")) exit(0, "The host is not affected.");

version = get_kb_item_or_exit("SMB/WindowsMediaPlayer");
if (!ereg(pattern:"^9\,[0-9]\,[0-9]\,[0-9]", string:version)) exit(0, "The host is not affected as it does not have Windows Media Player 9.x.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


path = hotfix_get_systemroot() + "\system32";
if (hotfix_check_fversion(path:path, file:"Wmp.dll", version:"9.0.0.3008", bulletin:bulletin, kb:kb) == HCF_OLDER)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
