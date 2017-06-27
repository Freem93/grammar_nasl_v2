#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34123);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-3007");
 script_bugtraq_id(31067);
 script_osvdb_id(47964);
 script_xref(name:"MSFT", value:"MS08-055");
 script_xref(name:"IAVB", value:"2008-B-0058");

 script_name(english:"MS08-055: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (955047)");
 script_summary(english:"Determines the version of MSO.dll.");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
 script_set_attribute(attribute:"description", value:
"The version of Microsoft Office running on the remote host is affected
by an argument injection vulnerability. By convincing a user to click
on a specially crafted OneNote URL, a remote attacker can exploit this
to execute arbitrary code or view or change data with current user
rights.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-055");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office XP, 2003, 2007 and
OneNote 2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "onenote_installed.nbin", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');

 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-055';
kbs = make_list("950130", "951944", "953404", "953405");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

vuln = 0;

share = '';
lastshare = '';
accessibleshare = FALSE;
office_versions = hotfix_check_office_version ();
if ( max_index(keys(office_versions)) > 0 )
{
 if (office_versions["10.0"] )
 {
  officesp = get_kb_item("SMB/Office/XP/SP");
  if (!isnull(officesp) && officesp == 3)
  {
    path = hotfix_get_officecommonfilesdir(officever:"10.0") + "\Microsoft Shared\Office10";
    dll = path + "\mso.dll";
    share = hotfix_path2share(path:path);
    lastshare = share;
    if (is_accessible_share(share:share))
    {
      accessibleshare = TRUE;
      res = hotfix_get_fversion(path:dll);
      if (res['error'] == HCF_OK)
      {
        ver = res['value'];
        if (int(ver[0]) == 10 && int(ver[1]) == 0 && int(ver[2]) < 6845)
        {
          vuln++;
          info =
            '\n  Product           : Microsoft Office 2002' +
            '\n  Path              : ' + path +
            '\n  Installed version : ' + join(ver, sep:'.') +
            '\n  Fixed version     : 10.0.6845.0\n';
          hotfix_add_report(info, bulletin:bulletin, kb:'953405');
        }
      }
    }
  }
 }
 if (office_versions["11.0"] )
 {
   officesp = get_kb_item("SMB/Office/2003/SP");
   if (!isnull(officesp) && (officesp == 2 || officesp == 3))
   {
     path = hotfix_get_officecommonfilesdir(officever:"11.0") + "\Microsoft Shared\Office11";
     dll = path + "\mso.dll";
     share = hotfix_path2share(path:path);
     if (share != lastshare || !accessibleshare)
     {
       lastshare = share;
       if (is_accessible_share(share:share))
       {
         accessibleshare = TRUE;
         res = hotfix_get_fversion(path:dll);
         if (res['error'] == HCF_OK)
         {
           ver = res['value'];
           if (int(ver[0]) == 11 && int(ver[1]) == 0 && int(ver[2]) < 8221)
           {
             vuln++;
             info =
               '\n  Product           : Microsoft Office 2003' +
               '\n  Path              : ' + path +
               '\n  Installed version : ' + join(ver, sep:'.') +
               '\n  Fixed version     : 11.0.8221.0\n';
             hotfix_add_report(info, bulletin:bulletin, kb:'953404');
           }
         }
       }
       else accessibleshare = FALSE;
     }
   }
 }
 if (office_versions["12.0"] )
 {
   officesp = get_kb_item("SMB/Office/2007/SP");
   if (!isnull(officesp) && (officesp == 0 || officesp == 1))
   {
     path = hotfix_get_officecommonfilesdir(officever:"12.0") + "\Microsoft Shared\Office12";
     dll = path + "\mso.dll";
     share = hotfix_path2share(path:path);
     if (share != lastshare || !accessibleshare)
     {
       lastshare = share;
       if (is_accessible_share(share:share))
       {
         accessibleshare = TRUE;
         res = hotfix_get_fversion(path:dll);
         if (res['error'] == HCF_OK)
         {
           ver = res['value'];
           if (int(ver[0]) == 12 && int(ver[1]) == 0 && int(ver[2]) < 6320)
           {
             vuln++;
             info =
               '\n  Product           : Microsoft Office 2007' +
               '\n  Path              : ' + path +
               '\n  Installed version : ' + join(ver, sep:'.') +
               '\n  Fixed version     : 12.0.6320.5000\n';
             hotfix_add_report(info, bulletin:bulletin, kb:'951944');
           }
         }
       }
       else accessibleshare = FALSE;
     }
   }
 }
}
hotfix_check_fversion_end();

onenote_installs = get_installs(app_name:'Microsoft OneNote');
if (onenote_installs[0] == IF_OK)
{
  foreach install (onenote_installs[1])
  {
    onenote_product = install['product'];
    onenote_sp = install['sp'];
    onenote_path = install['path'];
    onenote_version = install['version'];
    if (onenote_version == UNKNOWN_VER) continue;

    # Check Product
    if (onenote_product == '2007')
    {
      # Check Service Pack
      if (onenote_sp == '0' || onenote_sp == '1')
      {
        v = split(onenote_version, sep:'.', keep:FALSE);
        if (
          (int(v[0]) == 12 && int(v[1]) == 0 && int(v[2]) < 6316) ||
          (int(v[0]) == 12 && int(v[1]) == 0 && int(v[2]) == 6316 && int(v[3]) < 5000)
        )
        {
          vuln++;
          info =
            '\n  Product           : Microsoft OneNote 2007' +
            '\n  Path              : ' + onenote_path +
            '\n  Installed version : ' + onenote_version +
            '\n  Fixed version     : 12.0.6316.5000\n';
          hotfix_add_report(info, bulletin:bulletin, kb:'950130');
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
