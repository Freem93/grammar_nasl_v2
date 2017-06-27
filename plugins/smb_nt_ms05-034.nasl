#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18487);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-1215", "CVE-2005-1216", "CVE-2005-1907");
 script_bugtraq_id(13846, 13954, 13955, 13956);
 script_osvdb_id(17031, 17311, 17312, 17342);
 script_xref(name:"MSFT", value:"MS05-034");
 script_xref(name:"CERT", value:"367077");

 script_name(english:"MS05-034: Cumulative Update for ISA Server 2000 (899753)");
 script_summary(english:"Checks for hotfix 899753");

 script_set_attribute(attribute:"synopsis", value:
"A user can elevate his privileges.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a cumulative update for ISA Server 2000
that fixes several security flaws that could allow an attacker to
elevate his privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-034");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for ISA Server 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/02");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/06/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS05-034';
kb = '899753';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");

if (is_accessible_share ())
{
 if ( hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"3.0.1200.430", bulletin:bulletin, kb:kb) == HCF_OLDER )
 {
  set_kb_item(name:"SMB/Missing/MS05-034", value:TRUE);
  hotfix_security_warning();
 }
 hotfix_check_fversion_end();
}
else
{
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/430");
 if(!fix)
 {
  set_kb_item(name:"SMB/Missing/MS05-034", value:TRUE);
  hotfix_add_report(bulletin:bulletin, kb:kb);
  hotfix_security_warning();
 }
}
