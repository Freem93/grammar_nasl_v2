#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11920);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0820", "CVE-2003-0821");
 script_bugtraq_id(8835, 9010);
 script_osvdb_id(2801);
 script_xref(name:"MSFT", value:"MS03-050");
 script_xref(name:"MSKB", value:"830346");
 script_xref(name:"MSKB", value:"830347");
 script_xref(name:"MSKB", value:"830349");
 script_xref(name:"MSKB", value:"830350");
 script_xref(name:"MSKB", value:"830354");
 script_xref(name:"MSKB", value:"830356");

 script_name(english:"MS03-050: Word and/or Excel may allow arbitrary code to run (831527)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word and/or Microsoft
Excel that are subject to a flaw that could allow arbitrary code to be
run.

An attacker could use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue Word or Excel file
to the owner of this computer and have him open it.  Then the macros
contained in the Word file would bypass the security model of Word, and
would be executed.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-050");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 97, 2000 and
2002.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/11/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/11/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports("SMB/Office/Excel/Version", "SMB/Office/Word/Version", "Host/patch_management_checks");

 exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS03-050';
kbs = make_list("830346", "830347", "830349", "830350", "830354", "830356");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
port = get_kb_item("SMB/transport");

vuln = 0;
list = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(list))
{
 foreach item (keys(list))
 {
   v = item - 'SMB/Office/Excel/' - '/ProductPath';
   if( ereg(pattern:"^8\.0", string:v) )
   {
      # Excel 97 - fixed in 8.0.1.9904
      if( ereg(pattern:"^8\.0*0\.0*0\.", string:v) )
      {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:'830356');
      }
      else
      {
        last = ereg_replace(pattern:"^8\.0*0\.0*1\.([0-9]*)", string:v, replace:"\1");
        if ( int(last) < 9904 ) {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:'830356');
        }
      }
    }

    if ( ereg(pattern:"^9\.", string:v) )
    {
      # Excel 2000 - fixed in 9.0.08216
      last = ereg_replace(pattern:"^9\.0*0\.0*0\.(.*)", string:v, replace:"\1");
      if ( int(last) < 8216 )
      {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:'830349');
      }
    }

    if ( ereg(pattern:"^10\.", string:v ) )
    {
      # Excel 2002 - fixed in 10.0.5815.0
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 5815)
      {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:'830350');
      }
    }
  }
}

list = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/Word/' - '/ProductPath';
    if(ereg(pattern:"^10\..*", string:v))
    {
      # Word 2002 - updated in 10.0.5815.0
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 5815) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:'830346');
      }
    }
    else if(ereg(pattern:"^9\..*", string:v))
    {
       # Word 2000 - fixed in 9.00.00.8216
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8216) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:'830347');
      }
    }
    else if(ereg(pattern:"^9\..*", string:v))
    {
       # Word 97 - fixed in 8.0.0.9716
       sub =  ereg_replace(pattern:"^8\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
       if(sub != v && int(sub) < 9716) {
         vuln++;
         hotfix_add_report(bulletin:bulletin, kb:'830354');
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
