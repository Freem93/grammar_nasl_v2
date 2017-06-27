#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57274);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-2010");
  script_bugtraq_id(50950);
  script_osvdb_id(77669);
  script_xref(name:"MSFT", value:"MS11-088");
  script_xref(name:"IAVB", value:"2011-B-0146");

  script_name(english:"MS11-088: Vulnerability in Microsoft Office IME (Chinese) Could Allow Elevation of Privilege (2652016)");
  script_summary(english:"Checks version of Imsccfg.dll and Imsccore.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote Windows host
has a privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Office Input Method Editor (Chinese)
installed on the remote host has a privilege escalation vulnerability.
A local attacker could exploit this by utilizing the MSPY IME toolbar
in an unspecified manner, resulting in arbitrary code execution in
kernel mode."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS11-088");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Pinyin IME 2010, Office
Pinyin SimpleFast Style 2010, and Office Pinyin New Experience Style
2010."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:pinyin_simple_fast_style");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS11-088';
kbs = make_list('2596511', '2647540');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

common = hotfix_get_officecommonfilesdir(officever:"14.0");
if (!common) exit(1, 'hotfix_get_officecommonfilesdir() failed.');

share = hotfix_path2share(path:common);
ime_path = common + "\Microsoft Shared\IME14\IMESC";      # Pinyin IME bundled with Office 2010 Chinese
styles_path = common + "\Microsoft Shared\IME14WR\IMESC"; # Pinyin SimpleFast & New Experience Style (MSPY2010)

if (!is_accessible_share(share:share)) exit(1, 'Unable to connect to ' + share + ' share.');

# it's possible that both KBs need to be installed on the same system
res1 = hotfix_is_vulnerable(path:ime_path, file:"Imsccore.dll", version:"14.0.6009.1000", min_version:"14.0.0.0", bulletin:bulletin, kb:"2596511");
res2 = hotfix_is_vulnerable(path:styles_path, file:"Imsccfg.dll", version:"14.0.5810.1000", min_version:"14.0.0.0", bulletin:bulletin, kb:"2647540");

if (res1 || res2)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
