#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34402);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2008-3477", "CVE-2008-3471", "CVE-2008-4019");
 script_bugtraq_id(31702, 31705, 31706);
 script_osvdb_id(49076, 49077, 49078);
 script_xref(name:"MSFT", value:"MS08-057");

 script_name(english:"MS08-057: Microsoft Excel Multiple Method Remote Code Execution (956416)");
 script_summary(english:"Determines the version of Excel.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Excel.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Excel that is subject
to various flaws which could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Excel.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-057");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, XP, 2003 and
2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
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

bulletin = 'MS08-057';
kbs = make_list("955461", "955464", "955466", "955468", "955470", "955935");
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
      # Excel 2000 - fixed in 9.0.0.8972
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
        if(sub != v && int(sub) < 8972 ) {
          vuln++;
          kb = '955461';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Excel XP - fixed in 10.0.6847.0
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6847 ) {
          vuln++;
          kb = '955464';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
      # Excel 2003 - fixed in 11.0.8231.0
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
      {
        middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 8231 ) {
          vuln++;
          kb = '955466';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^12\..*", string:v))
    {
      # Excel 2007 - fixed in 12.0.6324.5001
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 0 && office_sp == 1))
      {
        middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        low =  ereg_replace(pattern:"^12\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
        if(middle != v && ( ( int(middle) < 6324  || ( int(middle) == 6324 && int(low) < 5001) ) ) ) {
          vuln++;
          kb = '955470';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
  }
}


#
# Excel Viewer
#
list = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    if (v && ereg(pattern:"^11\..*", string:v))
    {
      # Excel Viwever 2003 - fixed in 11.0.8231.0
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8231 ) {
        vuln++;
        kb = '955935';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
    else if (v && ereg(pattern:"^12\..*", string:v))
    {
      # Excel Viwever 2003 - fixed in 12.0.6325.5000
      middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6325) {
        vuln++;
        kb = '955468';
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
