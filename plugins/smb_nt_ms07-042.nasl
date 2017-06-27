#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25880);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2007-2223");
 script_bugtraq_id(25301);
 script_osvdb_id(36394);
 script_xref(name:"MSFT", value:"MS07-042");
 script_xref(name:"CERT", value:"361968");
 script_xref(name:"EDB-ID", value:"30493");

 script_name(english:"MS07-042: Vulnerability in Microsoft XML Core Services Could Allow Remote Code Execution (936227)");
 script_summary(english:"Determines the presence of update 936227");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that contains a flaw
in the Windows XML Core Services.

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
website or view a specially crafted email message.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-042");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(119,189);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-042';
kbs = make_list("936021", "936048");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if (!is_accessible_share()) exit(1, 'is_accessible_share() failed');

if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) > 0)
{
  if ( ( hotfix_check_fversion(file:"system32\Msxml3.dll", version:"8.90.1101.0", bulletin:bulletin, kb:'936021') == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml4.dll", version:"4.20.9847.0", bulletin:bulletin, kb:'936181') == HCF_OLDER ) ||
       # this actually covers KB936960 and KB936056
       ( hotfix_check_fversion(file:"system32\Msxml5.dll", version:"5.20.1081.0", bulletin:bulletin, kb:'936960') == HCF_OLDER ) ||
       ( hotfix_check_fversion(file:"system32\Msxml6.dll", version:"6.10.1200.0", bulletin:bulletin, kb:'933579') == HCF_OLDER ) )
 {
 set_kb_item(name:"SMB/Missing/MS07-042", value:TRUE);
 hotfix_security_hole();
 hotfix_check_fversion_end();
 exit(0);
 }

 hotfix_check_fversion_end();
}

 office_versions = hotfix_check_office_version ();
 if ( !office_versions )
  exit(0);

 if (!office_versions["11.0"]);
  exit (0);

 rootfile = hotfix_get_officecommonfilesdir(officever:'11.0');
 if (!rootfile) exit(0);

 if ( hotfix_check_fversion(path:rootfile, file:"\Microsoft Shared\Office11\msxml5.dll", version:"5.20.1081.0", bulletin:bulletin, kb:'936048') == HCF_OLDER )
 {
 set_kb_item(name:"SMB/Missing/MS07-042", value:TRUE);
 hotfix_security_hole();
 hotfix_check_fversion_end();
 exit(0);
 }
 hotfix_check_fversion_end();
 audit(AUDIT_HOST_NOT, 'affected');

