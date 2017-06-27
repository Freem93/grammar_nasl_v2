#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25902);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2007-0948");
 script_bugtraq_id(25298);
 script_osvdb_id(36389);
 script_xref(name:"MSFT", value:"MS07-049");

 script_name(english:"MS07-049: Vulnerability in Virtual PC and Virtual Server Could Allow Elevation of Privilege (937986)");
 script_summary(english:"Determines the version of Virtual PC/Server");

 script_set_attribute(attribute:"synopsis", value:
"A user can elevate his privileges on the virtual system.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Virtual PC or Virtual Server
that is vulerable to a heap overflow that could allow arbitrary code
to be run.

An attacker may use this to execute arbitrary code on the host
operating system or others guests.

To succeed, the attacker needs administrative privileges on the guest
operating system.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-049");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Virtual PC 2004 and Virtual
Server 2005.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:virtual_pc");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:virtual_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-049';
kbs = make_list("937986");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);
if ( ! is_accessible_share() ) exit(1);

path = hotfix_get_programfilesdir();
if ( ! path ) exit(1);


kb = '937986';
if ( ( hotfix_check_fversion(path:path, file:"Microsoft Virtual PC\Virtual PC.exe", version:"5.3.0.583", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual PC\Virtual PC.exe", version:"5.3.582.44", min_version:"5.3.582.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual Server\vssrvc.exe", version:"1.1.465.15", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual Server\vssrvc.exe", version:"1.1.465.106", min_version:"1.1.465.100", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path, file:"Microsoft Virtual Server\vssrvc.exe", version:"1.1.465.356", min_version:"1.1.465.300", bulletin:bulletin, kb:kb) == HCF_OLDER ) )
 {
 set_kb_item(name:"SMB/Missing/MS07-049", value:TRUE);
 hotfix_security_hole();
 }

hotfix_check_fversion_end();
