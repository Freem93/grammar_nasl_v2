#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21078);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2016/07/11 14:12:52 $");

 script_cve_id(
  "CVE-2005-4131",
  "CVE-2006-0028",
  "CVE-2006-0029",
  "CVE-2006-0030",
  "CVE-2006-0031",
  "CVE-2006-0009"
 );
 script_bugtraq_id(15926, 16181, 17000, 17091, 17100, 17101, 17108);
 script_osvdb_id(21568, 23899, 23900, 23901, 23902, 23903);
 script_xref(name:"MSFT", value:"MS06-012");

 script_name(english:"MS06-012: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (905413)");
 script_summary(english:"Determines the version of WinWord.exe / Excel.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that could
allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him open it.  Then a bug in the font
parsing handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-012");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/03/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-012';
kbs = make_list("905413", "905553", "905754", "905755", "905756", "905757");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
port = get_kb_item("SMB/transport");


kb = '905413';
vuln = 0;
#
# Word
#
list = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/Word/' - '/ProductPath';
    if(ereg(pattern:"^9\..*", string:v))
    {
      # Word 2000 - fixed in 9.00.00.8939
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = '905553';
        sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
        if(sub != v && int(sub) < 8939 ) {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }

    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Word XP - fixed in 10.0.6775.0
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = '905754';
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6775) {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
  }
}

#
# Excel
#
list = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/Excel/' - '/ProductPath';
    if(ereg(pattern:"^9\..*", string:v))
    {
      # Excel 2000 - fixed in 9.00.00.8938
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = '905757';
        sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
        if(sub != v && int(sub) < 8938 ) {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Excel XP - fixed in 10.0.6789.0
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = '905755';
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6789 ) {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
      # Excel 2003 - fixed in 11.0.8012.0
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        kb = '905756';
        middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 8012) {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
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
