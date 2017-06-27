#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14732);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2015/12/01 15:02:05 $");

 script_cve_id("CVE-2004-0573");
 script_bugtraq_id(11172);
 script_osvdb_id(9950);
 script_xref(name:"MSFT", value:"MS04-027");

 script_name(english:"MS04-027: Vulnerability in WordPerfect Converter (884933)");
 script_summary(english:"Determines the version of MSCONV97.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that contains
a flaw in its WordPerfect converter, that could allow an attacker to
execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a specially crafted
file to a user on the remote host and wait for him to open it using
Microsoft Office.

When opening the malformed file, Microsoft Office will encounter a
buffer overflow that could be exploited to execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-027");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/09/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS04-027';
kb = '884933';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

versions = hotfix_check_office_version ();

CommonFilesDirs = hotfix_get_commonfilesdir();
if ( ! CommonFilesDir ) exit(1, "Unable to get common files directory.");

vuln = FALSE;
foreach key (keys(CommonFilesDir))
{
  if ("9.0" >< key || "10.0" >< key)
  {
    dir = CommonFilesDir[key] + "\Microsoft Shared\TextConv";
    share = hotfix_path2share(path:dir);
    if (is_accessible_share(share:share))
    {
      if (hotfix_is_vulnerable(file:"MSCONV97.dll", version:"2003.1100.6252.0", path:dir, bulletin:bulletin, kb:kb))
      {
        vuln = TRUE;
      }
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS04-027", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
