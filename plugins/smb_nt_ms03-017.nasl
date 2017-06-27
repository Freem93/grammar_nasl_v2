#
# (C) Tenable Network Security, Inc.
#
# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP2
#	Media Player 7.1
#

include("compat.inc");

if (description)
{
 script_id(11595);
 script_version("$Revision: 1.40 $");
 script_cvs_date("$Date: 2017/05/25 13:29:26 $");

 script_cve_id("CVE-2003-0228");
 script_bugtraq_id(7517);
 script_osvdb_id(7738);
 script_xref(name:"MSFT", value:"MS03-017");
 script_xref(name:"CERT", value:"384932");
 script_xref(name:"MSKB", value:"817787");

 script_name(english:"MS03-017: Windows Media Player Skin Download Overflow (817787)");
 script_summary(english:"Checks the version of Media Player");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the media
player.");
 script_set_attribute(attribute:"description", value:
"The remote host is using a version of Windows Media player that is
vulnerable to a directory traversal attack through its handling of
'skins'.

An attacker could exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player.

To exploit this flaw, an attacker would need to craft a specially
malformed skin and send it to a user of this host, either directly by
email or by sending a URL pointing to it.

Affected Software :

 - Microsoft Windows Media Player 7.1
 - Microsoft Windows Media Player for Windows XP (Version 8.0)");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-017");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Media Player.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/07");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/05/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/07");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_player");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS03-017';
kb = "817787";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/WindowsVersion');
get_kb_item_or_exit("SMB/registry_full_access");

if (hotfix_check_sp(xp:2) <= 0) exit(0, "The host is not affected based on its version / service pack.");

version = get_kb_item_or_exit("SMB/WindowsMediaPlayer");


if (is_accessible_share())
{
  path = hotfix_get_programfilesdir() + "\Windows Media Player";

  if (hotfix_check_fversion(path:path, file:"Wmplayer.exe", version:"8.0.0.4490", min_version:"8.0.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER)
  {
    hotfix_security_hole();
    hotfix_check_fversion_end();

    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    exit(0);
  }
  hotfix_check_fversion_end();
}
else
{
  fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/wm817787");
  if (!fix)
  {
    if (
      defined_func("report_xml_tag") &&
      !isnull(bulletin) &&
      !isnull(kb)
    ) report_xml_tag(tag:bulletin, value:kb);

    hotfix_security_hole();

    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    exit(0);
  }
}

exit(0, "The host is not affected.");
