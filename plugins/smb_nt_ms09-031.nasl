#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39794);
  script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2009-1135");
  script_bugtraq_id(35631);
  script_osvdb_id(55836);
  script_xref(name:"MSFT", value:"MS09-031");
  script_xref(name:"IAVB", value:"2009-B-0031");

  script_name(english:"MS09-031: Vulnerability in Microsoft ISA Server 2006 Could Cause Elevation of Privilege (970953)");
  script_summary(english:"Checks version of wspsrv.exe");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote host contains an application that is affected by a
privilege escalation vulnerability.");
  script_set_attribute( attribute:"description",  value:
"The version of Microsoft Internet Security and Acceleration (ISA)
Server 2006 installed on the remote host may allow an unauthenticated
attacker with knowledge of administrator account usernames to gain
access to published resources in the context of such a user without
having to authenticate with the ISA server.

Note that successful exploitation of this issue requires that ISA be
configured for Radius One Time Password (OTP) authentication and
authentication delegation with Kerberos Constrained Delegation.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-031");
  script_set_attribute( attribute:"solution",  value:"Microsoft has released a set of patches for ISA Server 2006.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:isa_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-031';
kbs = make_list("971143");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");

share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);
if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");


if (
  # ISA Server 2006
  hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5723.514", min_version:"5.0.5723.0", bulletin:bulletin, kb:'971143') == HCF_OLDER ||
  hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5721.263", min_version:"5.0.5721.0", bulletin:bulletin, kb:'970811') == HCF_OLDER ||
  hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5720.174", min_version:"5.0.0.0", bulletin:bulletin, kb:'970811') == HCF_OLDER
)
{
  set_kb_item(name:"SMB/Missing/MS09-031", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
