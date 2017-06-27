#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34404);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-3466");
 script_bugtraq_id(31620);
 script_osvdb_id(49068);
 script_xref(name:"MSFT", value:"MS08-059");
 script_xref(name:"IAVB", value:"2008-B-0074");

 script_name(english:"MS08-059: Microsoft Host Integration Server (HIS) SNA RPC Request Remote Overflow (956695)");
 script_summary(english:"Determines the presence of update 956695");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Host
Integration Server (HIS).");
 script_set_attribute(attribute:"description", value:
"The remote host has HIS (Host Integration Server) installed.  The
version of this product contains a code execution vulnerability
in its RPC interface.

An attacker could exploit this flaw to execute arbitrary code on the
remote host by making rogue RPC queries.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-059");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for HIS 2000, 2003 and 2006.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(287);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:host_integration_server");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-059';
kbs = make_list("956695");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


kb       = '956695';

if (is_accessible_share())
{
 programfiles = hotfix_get_programfilesdir();
 if (
      hotfix_check_fversion(file:"Rpcdetct.dll", version:"5.0.1.798", path:programfiles + "\Host Integration Server\System", bulletin:bulletin, kb:kb) == HCF_OLDER ||   # 2000
      hotfix_check_fversion(file:"Rpcdetct.dll", version:"6.0.2430.0", min_version:"6.0.2400.0", path:programfiles + "\Microsoft Host Integration Server\System", bulletin:bulletin, kb:kb) == HCF_OLDER || # 2004 SP1 server
      hotfix_check_fversion(file:"Hisservicelib.dll", version:"6.0.2430.0", min_version:"6.0.2400.0", path:programfiles + "\Microsoft Host Integration Server\System", bulletin:bulletin, kb:kb) == HCF_OLDER || # 2004 SP1 client
      hotfix_check_fversion(file:"Hisservicelib.dll", version:"6.0.2119.0", min_version:"6.0.0.0", path:programfiles + "\Microsoft Host Integration Server\System", bulletin:bulletin, kb:kb) == HCF_OLDER || # 2004 client
      hotfix_check_fversion(file:"Rpcdetct.dll", version:"7.0.2900.0", min_version:"7.0.0.0", path:programfiles + "\Microsoft Host Integration Server 2006\System", bulletin:bulletin, kb:kb)  == HCF_OLDER # 2006
     )
 {
 set_kb_item(name:"SMB/Missing/MS08-059", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
 exit (0);
}
