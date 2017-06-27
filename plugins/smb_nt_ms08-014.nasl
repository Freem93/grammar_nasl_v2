#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31413);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
   "CVE-2008-0111",
   "CVE-2008-0112",
   "CVE-2008-0114",
   "CVE-2008-0115",
   "CVE-2008-0116",
   "CVE-2008-0117",
   "CVE-2008-0081"
 );
 script_bugtraq_id(27305, 28094, 28095, 28166, 28167, 28168, 28170);
 script_osvdb_id(
   40344,
   42722,
   42723,
   42724,
   42725,
   42730,
   42731,
   42732
 );
 script_xref(name:"MSFT", value:"MS08-014");

 script_name(english:"MS08-014: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (949029)");
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
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-014");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, XP, 2003 and
2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
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

bulletin = 'MS08-014';
kbs = make_list("943889", "943985", "946974", "946976", "946979");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
port = get_kb_item("SMB/transport");



#
# Excel
#
vuln = 0;
list = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/Excel/' - '/ProductPath';
    if(ereg(pattern:"^9\..*", string:v))
    {
      # Excel 2000 - fixed in 9.0.0.8968
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
        if(sub != v && int(sub) < 8968 ) {
          vuln++;
          kb = '946979';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Excel XP - fixed in 10.0.6841.0
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6841 ) {
          vuln++;
          kb = '946976';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
      # Excel 2003 - fixed in 11.0.8169.0  (SP3)
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 2)
      {
        middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 8169) {
          vuln++;
          kb = '943985';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^12\..*", string:v))
    {
      # Excel 2007 - fixed in 12.0.6300.5000
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 0)
      {
        middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        low =  ereg_replace(pattern:"^12\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
        # 12.0.6214.100 (SP1) is not affected
        if(middle != v && ( int(middle) < 6214 || int(middle) == 6124 && int(low) < 1000) ) {
          vuln++;
          kb = '946974';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
  }
}


#
# Excel Viever
#
list = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    if (v && ereg(pattern:"^11\..*", string:v))
    {
      # Excel Viwever 2003 - fixed in 11.0.8169.0  (SP3)
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8169) {
        vuln++;
        kb = '943889';
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
audit(AUDIT_HOST_NOT, 'affected');
