#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11832);
 script_version("$Revision: 1.43 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0347");
 script_bugtraq_id(8534);
 script_osvdb_id(12652);
 script_xref(name:"MSFT", value:"MS03-037");
 script_xref(name:"CERT", value:"804780");
 script_xref(name:"MSKB", value:"822715");

 script_name(english:"MS03-037: Visual Basic for Application Overflow (822715)");
 script_summary(english:"Determines the version of vbe.dll and vbe6.dll");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through VBA.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Basic for
Applications that is vulnerable to a buffer overflow when handling
malformed documents.

An attacker may exploit this flaw to execute arbitrary code on this
host by sending a malformed file to a user of the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-037");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/09/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/04");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic_software_development_kit");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");

 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS03-037';
kb = '822715';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


common = hotfix_get_commonfilesdir();
if ( ! common ) exit(1, "Unable to get common files directory.");

vba5 = common + "\Microsoft Shared\VBA";
vba6 = common + "\Microsoft Shared\VBA\VBA6";

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  hotfix_is_vulnerable(path:vba5, file:"vbe.dll", min_version:"5.0.0.0", version:"5.0.78.15", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(path:vba6, file:"vbe6.dll", min_version:"6.0.0.0", version:"6.4.99.69", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS03-037", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}
