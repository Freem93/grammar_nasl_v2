#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34744);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/12/09 20:55:00 $");

 script_cve_id("CVE-2007-0099", "CVE-2008-4029", "CVE-2008-4033");
 script_bugtraq_id(21872, 32155, 32204);
 script_osvdb_id(32627, 49926, 50279);
 script_xref(name:"IAVA", value:"2008-A-0084");
 script_xref(name:"MSFT", value:"MS08-069");

 script_name(english:"MS08-069: Vulnerabilities in Microsoft XML Core Services Could Allow Remote Code Execution (955218)");
 script_summary(english:"Determines the presence of update 955218");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that contains a flaw
in the Windows XML Core Services.

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
website or view a specially crafted email message.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-069");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200, 362);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/11/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-069';
kbs = make_list("951550", "955069");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (is_accessible_share())
{
  if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3, win7:2) > 0)
  {
    if ( ( hotfix_check_fversion(file:"system32\Msxml3.dll", version:"8.100.1048.0", bulletin:bulletin, kb:'955069') == HCF_OLDER ) ||
         ( hotfix_check_fversion(file:"system32\Msxml4.dll", version:"4.20.9870.0", bulletin:bulletin, kb:'954430') == HCF_OLDER ) ||
         ( hotfix_check_fversion(file:"system32\Msxml5.dll", version:"5.20.1087.0", bulletin:bulletin, kb:'951535') == HCF_OLDER ) ||
         ( hotfix_check_fversion(file:"system32\Msxml6.dll", version:"6.20.1099.0", bulletin:bulletin, kb:'954459') == HCF_OLDER ) )
   {
   set_kb_item(name:"SMB/Missing/MS08-069", value:TRUE);
   hotfix_security_hole();
   hotfix_check_fversion_end();
   exit(0);
   }

   hotfix_check_fversion_end();
 }


 office_version = hotfix_check_office_version ();
 if ( !office_version )
  exit(0);

 rootfiles = hotfix_get_officecommonfilesdir();
 if ( ! rootfiles )
  exit(0);

 if (!office_version["11.0"] && !office_version["12.0"])
  exit (0);

 vuln = FALSE;
 if (office_version["11.0"])
 {
   if (typeof(rootfiles) == 'array') rootfile = rootfiles["11.0"];
   else rootfile = rootfiles;
   if (office_version["11.0"] && hotfix_check_fversion(path:rootfile["11.0"], file:"\Microsoft Shared\Office11\msxml5.dll", version:"5.20.1087.0", bulletin:bulletin, kb:'951550') == HCF_OLDER )
     vuln = TRUE;
 }
 else if (office_versions["12.0"])
 {
   if (typeof(rootfiles) == 'array') rootfile = rootfiles["12.0"];
   else rootfile = rootfiles;
   if (office_version["12.0"] && hotfix_check_fversion(path:rootfile["12.0"], file:"\Microsoft Shared\Office11\msxml5.dll", version:"5.20.1087.0", bulletin:bulletin, kb:'951550') == HCF_OLDER )
     vuln = TRUE;
 }
 if (vuln)
 {
   set_kb_item(name:"SMB/Missing/MS08-069", value:TRUE);
   hotfix_security_hole();
   hotfix_check_fversion_end();
   exit(0);
 }
 hotfix_check_fversion_end();
 audit(AUDIT_HOST_NOT, 'affected');
}
