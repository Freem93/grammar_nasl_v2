#
# Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(31414);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-0110");
 script_bugtraq_id(28147);
 script_osvdb_id(42710);
 script_xref(name:"CERT", value:"393305");
 script_xref(name:"MSFT", value:"MS08-015");

 script_name(english:"MS08-015: Vulnerability in Microsoft Outlook Could Allow Remote Code Execution (949031)");
 script_summary(english:"Determines the version of OutLook");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of outlook or exchange that is vulnerable
to a bug when processing a specially malformed URI mailto link, which can let an
attacker execute arbitrary code on the remote host by sending a specially crafted
email.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-015");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook 2000, XP, 2003 and
2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-015';
kbs = make_list("945432", "946983", "946985", "946986");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


versions = hotfix_check_outlook_version();
vuln = 0;
share = '';
lastshare = '';
accessibleshare = FALSE;
if (versions)
{
  foreach install (keys(versions))
  {
    path = versions[install];
    version = install - 'SMB/Office/Outlook/' - '/Path';
    share = hotfix_path2share(path:path);
    if (share != lastshare || !accessibleshare)
    {
      accessibleshare = FALSE;
      lastshare = share;
      if (!is_accessible_share(share:share)) continue;
      accessibleshare = TRUE;
    }
    if (accessibleshare)
    {
      if (version == "9.0")
      {
        if ( hotfix_check_fversion(path:path, file:"Outllib.dll", version:"9.0.0.8968") == HCF_OLDER )
        {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:'946986');
        }
      }
      else if (version == "10.0")
      {
        if ( hotfix_check_fversion(path:path, file:"Outllib.dll", version:"10.0.6838.0") == HCF_OLDER )
        {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:'946985');
        }
      }
      else if (version == "11.0")
      {
        if ( hotfix_check_fversion(path:path, file:"Outllib.dll", version:"11.0.8206.0") == HCF_OLDER )
        {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:'945432');
        }
      }
      else if (version == "12.0")
      {
        if ( hotfix_check_fversion(path:path , file:"Outlook.exe", version:"12.0.6300.5000") == HCF_OLDER )
        {
          vuln++;
          hotfix_add_report(bulletin:bulletin, kb:'946983');
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
