#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31046);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2008-0102", "CVE-2008-0104");
 script_bugtraq_id(27739, 27740);
 script_osvdb_id(41446, 41447);
 script_xref(name:"MSFT", value:"MS08-012");

 script_name(english:"MS08-012: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (947085)");
 script_summary(english:"Determines the version of MSPUB.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Publisher.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Publisher that may
allow arbitrary code to be run on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him open it.  Then a bug in the font
parsing handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-012");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Publisher 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-012';
kbs = make_list("946216", "946254", "946255");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = kb_smb_transport();



#
# PowerPoint
#
vuln = 0;
list = get_kb_list("SMB/Office/Publisher/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/Publisher/' - '/ProductPath';
    if(ereg(pattern:"^9\..*", string:v))
    {
      # Publisher 2000 - fixed in 9.00.00.8931
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8931 ) {
        vuln++;
        kb = '946255';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Publisher XP - fixed in 10.0.6840.0
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6840) {
        vuln++;
        kb = '946216';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
       # Publisher 2003 - fixed in 11.0.8200.0
       middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
       if(middle != v && int(middle) < 8200) {
         vuln++;
         kb = '946254';
         hotfix_add_report(bulletin:bulletin, kb:kb);
       }
    }
  }
}

office_versions = hotfix_check_office_version ();
share = '';
lastshare = '';
accessibleshare = FALSE;
foreach office_version (keys(office_versions))
{
  path = '';
  rootfile = hotfix_get_officeprogramfilesdir(officever:office_version);
  if (!rootfile) continue;

  if ( "9.0" >< office_version)
	{
	  path  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:'\\1\\Microsoft Office\\Office\\', string:rootfile);
	}
  else if ( "10.0" >< office_version )
	  path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:'\\1\\Microsoft Office\\Office10\\', string:rootfile);
  else if ( "11.0" >< office_version )
	  path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:'\\1\\Microsoft Office\\Office11\\', string:rootfile);

  if (path)
  {
    share = hotfix_path2share(path:rootfile);
    if (share != lastshare || !accessibleshare)
    {
      accessibleshare = FALSE;
      lastshare = share;
      if (!is_accessible_share(share:share))
      {
        continue;
      }
      accessibleshare = TRUE;
    }

    if (accessibleshare)
    {
      if ("9.0" >< office_version)
      {
        if (hotfix_check_fversion(path:path, file:"Prtf9.dll", version:"9.0.0.8929") == HCF_OLDER)
        {
          vuln++;
          kb = '946255';
          hotfix_add_report('\nPath : '+share-'$'+':'+path+'Prtf9.dll'+
                            '\nVersion : '+join(v, sep:'.')+
                            '\nShould be : 9.0.0.8929\n', bulletin:bulletin, kb:kb);
        }
      }
      else if ("10.0" >< office_version)
      {
        if (hotfix_check_fversion(path:path, file:"Ptxt9.dll", version:"10.0.6840.0") == HCF_OLDER)
        {
          vuln++;
          kb = '946216';
          hotfix_add_report('\nPath : '+share-'$'+':'+path+'Ptxt9.dll'+
                            '\nVersion : '+join(v, sep:'.')+
                            '\nShould be : 10.0.6840.0\n', bulletin:bulletin, kb:kb);
        }
      }
      else if ("11.0" >< office_version)
      {
        if (hotfix_check_fversion(path:path, file:"Prtf9.dll", version:"11.0.8200.0") == HCF_OLDER)
        {
          vuln++;
          kb = '946254';
          hotfix_add_report('\nPath : '+share-'$'+':'+path+'Prtf9.dll'+
                            '\nVersion : '+join(v, sep:'.')+
                            '\nShould be : 11.0.8200.0\n', bulletin:bulletin, kb:kb);
        }
      }
    }
  }
}
hotfix_check_fversion_end();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
