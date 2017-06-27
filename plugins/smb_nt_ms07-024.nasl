#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25163);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/08/03 13:48:53 $");

 script_cve_id("CVE-2007-0035", "CVE-2007-0870", "CVE-2007-1202");
 script_bugtraq_id(22567, 23804, 23836);
 script_osvdb_id(33196, 34387, 34388);
 script_xref(name:"MSFT", value:"MS07-024");
 script_xref(name:"CERT", value:"260777");
 script_xref(name:"CERT", value:"332404");
 script_xref(name:"CERT", value:"555489");

 script_name(english:"MS07-024: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (934232)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that could allow
arbitrary code to be run.

An attacker could use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-024");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Word 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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

bulletin = 'MS07-024';
kbs = make_list("934181", "934392", "934394");
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
    # Word 2000 - fixed in 9.0.0.8961
    office_sp = get_kb_item("SMB/Office/2000/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8961 ) {
        vuln++;
        info =
          '\n  Product           : Excel 2000' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 9.0.0.8961\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'934392');
      }
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Word XP - fixed in 10.0.6829.0
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6829)  {
        vuln++;
        info =
          '\n  Product           : Excel 2002' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 10.0.6829.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'934394');
      }
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # Word 2003 - fixed in 11.0.8134.0
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8134) {
        vuln++;
        info =
          '\n  Product           : Excel 2003' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 11.0.8134.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'934181');
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
