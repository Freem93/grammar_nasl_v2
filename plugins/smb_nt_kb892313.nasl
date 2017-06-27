#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18085);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");
 
  script_bugtraq_id(13607);

  script_name(english:"MS KB892313: DRM Update in Windows Media Player May Facilitate Spyware Infections");
  script_summary(english:"Checks the version of Media Player.");
 
  script_set_attribute(attribute:"synopsis", value:
"It is possible to install spyware on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows Media Player 9 or
Windows Media Player 10 that is missing a security update. It is,
therefore, affected by a vulnerability that allows an attacker to
infect the remote host with spyware. An attacker can exploit this flaw
by crafting malformed WMP files which will cause Windows Media Player
to redirect the user to a malicious website when attempting to acquire
a license to read the file.");
  script_set_attribute(attribute:"see_also", value:"http://www.benedelman.org/news/010205-1.html");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/892313");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update referenced in the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:windows_media_player");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/WindowsMediaPlayer");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

port = kb_smb_transport ();

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);

if ( ! is_accessible_share() ) exit(0);


if (ereg(string:version, pattern:"^9,0,0,.*"))
{
 if ( hotfix_check_sp(xp:3, win2k:5, win2003:2) <= 0 ) exit(0);
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmp.dll", version:"9.0.0.3263", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wmp.dll", version:"9.0.0.3263", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmp.dll", version:"9.0.0.3263", min_version:"9.0.0.0", dir:"\system32") )
    security_hole(port);

}

if (ereg(string:version, pattern:"^10,0,0,.*"))
{
 if ( hotfix_check_sp(xp:3, win2k:5, win2003:2) <= 0 ) exit(0);

  if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmp.dll", version:"10.0.0.3701", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wmp.dll", version:"10.0.0.3701", min_version:"10.0.0.0", dir:"\system32") )
    security_hole(port);
}
   hotfix_check_fversion_end(); 
