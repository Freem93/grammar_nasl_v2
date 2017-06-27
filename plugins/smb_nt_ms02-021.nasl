#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11325);
 script_version("$Revision: 1.45 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-1056");
 script_bugtraq_id(4397);
 script_osvdb_id(2061);
 script_xref(name:"MSFT", value:"MS02-021");
 script_xref(name:"MSKB", value:"321804");

 script_name(english:"MS02-021: Word Mail Reply Arbitrary Script Execution (321804)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Word.");
 script_set_attribute(attribute:"description", value:
"Outlook 2000 and 2002 provide the option to use Microsoft Word as the
email editor when creating and editing email in RTF or HTML.

There is a flaw in some versions of Word that could allow an attacker to
execute arbitrary code when the user replies to a specially formed
message using Word.

An attacker could use this flaw to execute arbitrary code on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-021");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000 and 2002.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/31");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/04/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/06");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports("SMB/Office/Word/Version", "Host/patch_management_checks");

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-021';
kb       = '321804';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

list = get_kb_list_or_exit("SMB/Office/Word/*/ProductPath");

port = kb_smb_transport();


vuln = 0;
foreach item (keys(list))
{
  v = item - 'SMB/Office/Word/' - '/ProductPath';
  if(strlen(v))
  {
    if(ereg(pattern:"^9\..*", string:v))
    {
      # Word 2000 - patched in WinWord 9.0.6328
      middle =  ereg_replace(pattern:"^9\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      minor =   ereg_replace(pattern:"^9\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
      if(middle == 0 && minor < 6328) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Word 2002 - updated in 10.0.4009.3501

      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      minor  =  ereg_replace(pattern:"^10\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
      if(middle < 4009) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
      else if(middle == 4009 && minor < 3501) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');


