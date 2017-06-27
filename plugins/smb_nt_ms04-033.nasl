#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if( description)
{
 script_id(15458);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/07/14 14:10:24 $");

 script_cve_id("CVE-2004-0846");
 script_bugtraq_id(11373);
 script_osvdb_id(10694);
 script_xref(name:"MSFT", value:"MS04-033");

 script_name(english:"MS04-033: Microsoft Excel Code Execution (886836)");
 script_summary(english:"Determines if hotfix 886836 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Excel.");
 script_set_attribute(attribute:"description", value:

"The remote host has a version of Microsoft Excel that is vulnerable to
a code execution issue.  An attacker could exploit this flaw to execute
arbitrary code on the remote host with the privileges of the user
opening the file.

To exploit this flaw, an attacker would need to send a malformed Excel
file to a victim on the remote host and wait for him to open it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-033");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Excel 2000 and 2002.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports("Host/patch_management_checks");

 exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-033';
kb = '886836';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");
list = get_kb_list_or_exit("SMB/Office/Excel/*/ProductPath");


vuln = 0;
foreach item (keys(list))
{
  v = item - 'SMB/Office/Excel/' - '/ProductPath';
  if ( v )
  {
    if ( ereg(pattern:"^9\.", string:v) )
    {
      # Excel 2000 - fixed in 9.0.0.8924
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        last = ereg_replace(pattern:"^9\.0*0(\.0*0)*\.([0-9]*)$", string:v, replace:"\2");
        if ( int(last) < 8924 )
        {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }

    if ( ereg(pattern:"^10\.", string:v ) )
    {
      # Excel 2002 - fixed in 10.0.6501.0 (fixed in SP3 and version 10.0.6713.0)
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 2)
      {
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6501){
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
