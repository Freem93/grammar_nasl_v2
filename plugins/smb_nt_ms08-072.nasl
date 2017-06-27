#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35071);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/12/09 20:55:00 $");

 script_cve_id(
   "CVE-2008-4024",
   "CVE-2008-4025",
   "CVE-2008-4026",
   "CVE-2008-4027",
   "CVE-2008-4030",
   "CVE-2008-4028",
   "CVE-2008-4031",
   "CVE-2008-4837"
 );
 script_bugtraq_id(
   32579,
   32580,
   32581,
   32583,
   32584,
   32585,
   32594,
   32642
 );
 script_osvdb_id(
  50590,
  50591,
  50592,
  50593,
  50595,
  50596,
  50597,
  50598,
  52690
 );
 script_xref(name:"MSFT", value:"MS08-072");

 script_name(english:"MS08-072: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (957173)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that may allow
arbitrary code to be run on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him open it.  Then a bug in the word record
parsing handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-072");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Word.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
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

bulletin = 'MS08-072';
kbs = make_list("956328", "956329", "956357", "956358", "956366");
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
      # Word 2000 - fixed in 9.0.0.8974
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
        if(sub != v && int(sub) < 8974 ) {
          vuln++;
          kb = '956328';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Word XP - fixed in 10.0.6850.0
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6850 ) {
          vuln++;
          kb = '956329';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
      # Word 2003 - fixed in 11.0.8237.0 :
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 8237 ) {
          vuln++;
          kb = '956357';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^12\..*", string:v))
    {
      # Word 2007 - fixed in 12.0.6331.5000
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
      {
        middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6331 ) {
          vuln++;
          kb = '956358';
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
    if ( v && ereg(pattern:"^11\..*", string:v))
    {
      # Word Viewer 2003 - fixed in 11.0.8241.0
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8241 ) {
        vuln++;
        kb = '956366';
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
