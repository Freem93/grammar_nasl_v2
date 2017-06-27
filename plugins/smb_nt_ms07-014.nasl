#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24338);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2006-5994", "CVE-2006-6456", "CVE-2006-6561", "CVE-2007-0208", "CVE-2007-0209", "CVE-2007-0515");
 script_bugtraq_id(21451, 21518, 21589, 22225, 22477, 22482);
 script_osvdb_id(30824, 30825, 31900, 33270, 34385, 34386);
 script_xref(name:"MSFT", value:"MS07-014");
 script_xref(name:"CERT", value:"166700");
 script_xref(name:"CERT", value:"167928");
 script_xref(name:"CERT", value:"412225");
 script_xref(name:"CERT", value:"996892");
 script_xref(name:"EDB-ID", value:"2922");
 script_xref(name:"EDB-ID", value:"29524");

 script_name(english:"MS07-014: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (929434)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that could allow
arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-014");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Word 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/06");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-014';
kbs = make_list("929057", "929061", "929139");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");


#
# Word
#
vuln = 0;
list = get_kb_list_or_exit("SMB/Office/Word/*/ProductPath");
foreach item (keys(list))
{
  v = item - 'SMB/Office/Word/' - '/ProductPath';
  if(ereg(pattern:"^9\..*", string:v))
  {
    # Word 2000 - fixed in 9.00.00.8958
    office_sp = get_kb_item("SMB/Office/2000/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8958 ) {
        vuln++;
        info =
          '\n  Product           : Word 2000' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 9.00.00.8958\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'929139');
      }
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Word XP - fixed in 10.0.6826.0
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6826) {
        vuln++;
        info =
          '\n  Product           : Word 2002' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 10.0.6826.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'929061');
      }
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # Word 2003 - fixed in 11.0.8125.0
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8125) {
        vuln++;
        info =
          '\n  Product           : Word 2003' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 11.0.8125.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'929057');
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
