#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23998);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/07/20 14:03:38 $");

 script_cve_id("CVE-2007-0027", "CVE-2007-0028", "CVE-2007-0029", "CVE-2007-0030", "CVE-2007-0031");
 script_bugtraq_id(21856, 21877, 21922, 21925, 21952);
 script_osvdb_id(31249, 31255, 31256, 31257, 31258);
 script_xref(name:"MSFT", value:"MS07-002");
 script_xref(name:"CERT", value:"302836");
 script_xref(name:"CERT", value:"493185");
 script_xref(name:"CERT", value:"625532");
 script_xref(name:"CERT", value:"749964");
 script_xref(name:"EDB-ID", value:"3193");

 script_name(english:"MS07-002: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (927198)");
 script_summary(english:"Determines the version of Excel.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Excel.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Excel that is subject
to various flaws that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Excel.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-002");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/01/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
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

bulletin = 'MS07-002';
kbs = make_list("925257", "925523", "925524");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");


#
# Excel
#
vuln = 0;
list = get_kb_list_or_exit("SMB/Office/Excel/*/ProductPath");
foreach item (keys(list))
{
  v = item - 'SMB/Office/Excel/' - '/ProductPath';
  if(ereg(pattern:"^9\..*", string:v))
  {
    # Excel 2000 - fixed in 9.00.00.8955
    office_sp = get_kb_item("SMB/Office/2000/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8955 ) {
        vuln++;
        info =
          '\n  Product           : Excel 2000' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 9.00.00.8955\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'925524');
      }
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Excel XP - fixed in 10.0.6823.0
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6823) {
        vuln++;
        info =
          '\n  Product           : Excel 2002' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 10.0.6823.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'925523');
      }
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # Excel 2003 - fixed in 11.0.8117.0
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8117) {
        vuln++;
        info =
          '\n  Product           : Excel 2003' +
          '\n  Installed version : ' + v +
          '\n  Fixed version     : 11.0.8117.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:'925257');
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
