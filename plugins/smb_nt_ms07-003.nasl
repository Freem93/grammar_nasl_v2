#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23999);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2006-1305", "CVE-2007-0033", "CVE-2007-0034");
 script_bugtraq_id(21931, 21936, 21937);
 script_osvdb_id(31252, 31253, 31254);
 script_xref(name:"MSFT", value:"MS07-003");
 script_xref(name:"CERT", value:"271860");
 script_xref(name:"CERT", value:"476900");
 script_xref(name:"CERT", value:"617436");

 script_name(english:"MS07-003: Vulnerabilities in Microsoft Outlook Could Allow Remote Code Execution (925938)");
 script_summary(english:"Determines the version of OutLook");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of outlook or exchange that is vulnerable
to a bug in the VEVENT record handling routine that could allow an attacker execute
arbitrary code on the remote host by sending a specially crafted email.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-003");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook 2000, 2002 and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/01/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-003';
kbs = make_list("921593", "921594", "924085");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


versions = hotfix_check_outlook_version();
vuln = 0;
if (versions)
{
  foreach item (keys(versions))
  {
    version = item - 'SMB/Office/Outlook/' - '/Path';
    path = versions[item];
    if (version == "9.0")
    {
      if ( hotfix_check_fversion(path:path, file:"Outllib.dll", version:"9.0.0.8954", bulletin:bulletin, kb:"921593") == HCF_OLDER )
        vuln++;
    }
    else if (version == "10.0")
    {
      if ( hotfix_check_fversion(path:path, file:"Outllibr.dll", version:"10.0.6822.0", bulletin:bulletin, kb:"921594") == HCF_OLDER )
        vuln++;
    }
    else if (version == "11.0")
    {
      if ( hotfix_check_fversion(path:path, file:"Outllib.dll", version:"11.0.8118.0", bulletin:bulletin, kb:"924085") == HCF_OLDER )
        vuln++;
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
