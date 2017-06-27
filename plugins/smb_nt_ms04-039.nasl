#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15714);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/07/20 14:03:38 $");

 script_cve_id("CVE-2004-0892");
 script_bugtraq_id(11605);
 script_osvdb_id(11579);
 script_xref(name:"MSFT", value:"MS04-039");

 script_name(english:"MS04-039: ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)");
 script_summary(english:"Checks for hotfix Q888258");

 script_set_attribute(attribute:"synopsis", value:"It is possible to spoof the content of the remote proxy server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running ISA Server 2000, an HTTP proxy.  The remote
version of this software is vulnerable to content spoofing attacks.

An attacker could lure a victim to visit a malicious website and the
user could believe is visiting a trusted web site.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-039");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for ISA Server 2000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/11/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:proxy_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:small_business_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-039';
kb = '888258';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");


if (is_accessible_share ())
{
 if ( hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"3.0.1200.408", bulletin:bulletin, kb:kb) == HCF_OLDER )
 {
  set_kb_item(name:"SMB/Missing/MS04-039", value:TRUE);
  hotfix_security_warning();
 }
 hotfix_check_fversion_end();
}
else
{
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
 if(!fix)
 {
  set_kb_item(name:"SMB/Missing/MS04-039", value:TRUE);
  hotfix_add_report(bulletin:bulletin, kb:kb);
  hotfix_security_warning();
 }
}
