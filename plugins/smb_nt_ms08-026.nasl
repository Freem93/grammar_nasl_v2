#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(32310);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2008-1091","CVE-2008-1434");
 script_bugtraq_id(29104, 29105);
 script_osvdb_id(45031, 45032);
 script_xref(name:"CERT", value:"543907");
 script_xref(name:"MSFT", value:"MS08-026");

 script_name(english:"MS08-026: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (951207)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that is subject
to a flaw that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-026");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word 2000, XP, 2003 and
2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');

 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-026';
kbs = make_list("950113", "950241", "950243", "950250", "950625");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");



#
# Word
#
vuln = 0;
list = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/Word/' - '/ProductPath';
    if(ereg(pattern:"^9\..*", string:v))
    {
      # Word 2000 - fixed in 9.0.0.8970
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
        if(sub != v && int(sub) < 8970 ) {
          vuln++;
          kb = '950250';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Word XP - fixed in 10.0.6843.0
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6843) {
          vuln++;
          kb = '950243';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
      # Word 2003 - fixed in 11.0.8215.0 (SP3)
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
      {
        middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 8215) {
          vuln++;
          kb = '950241';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^12\..*", string:v))
    {
      # Word 2007 - fixed in 12.0.6308.500
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
      {
        middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6308) {
          vuln++;
          kb = '950113';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
  }
}

#
# Word Viewer
#
list = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/WordViewer/' - '/ProductPath';
    # Word Viewer 2003 - fixed in 11.0.8169.0 (SP3)
    middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
    if(middle != v && int(middle) < 8169) {
      vuln++;
      kb = '950625';
      hotfix_add_report(bulletin:bulletin, kb:kb);
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
