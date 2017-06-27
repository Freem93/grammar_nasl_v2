#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36154);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2009-0077", "CVE-2009-0237");
  script_bugtraq_id(34414, 34416);
  script_osvdb_id(53636, 53637);
  script_xref(name:"IAVT", value:"2009-T-0022");
  script_xref(name:"MSFT", value:"MS09-016");

  script_name(english:"MS09-016: Vulnerabilities in Microsoft ISA Server and Forefront Threat Management Gateway Could Cause Denial of Service (961759)");
  script_summary(english:"Checks version of wspsrv.exe");

  script_set_attribute( attribute:"synopsis",  value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute( attribute:"description",    value:
"The version of Microsoft ISA Server or Forefront Threat Management
Gateway installed on the remote host is affected by one or both of the
following vulnerabilities :

  - By sending a series of specially crafted packets, an
    anonymous remote attacker can create orphaned open
    sessions in the firewall engine, thereby denying
    service to legitimate users. (CVE-2009-0077)

  - A non-persistent cross-site scripting vulnerability
    exists in the application due to its failure to sanitize
    input to its 'cookieauth.dll' script. (CVE-2009-0237)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-016");
  script_set_attribute(  attribute:"solution",   value:
"Microsoft has released a set of patches for ISA Server 2004 and 2006
as well as Forefront Threat Management Gateway.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_threat_management_gateway");
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

bulletin = 'MS09-016';
kbs = make_list("9698075");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");


if (is_accessible_share())
{
  if (
    # Microsoft Forefront Threat Management Gateway Medium Business Edition
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"6.0.6417.153", min_version:"6.0.0.0", bulletin:bulletin, kb:"9698075") == HCF_OLDER ||

    # ISA Server 2006
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5723.511", min_version:"5.0.5723.0", bulletin:bulletin, kb:"968078") == HCF_OLDER ||
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5721.261", min_version:"5.0.5721.0", bulletin:bulletin, kb:"968078") == HCF_OLDER ||
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"5.0.5720.172", min_version:"5.0.0.0", bulletin:bulletin, kb:"968078") == HCF_OLDER ||

    # ISA Server 2004
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"4.0.3445.909", min_version:"4.0.3000.0", bulletin:bulletin, kb:"960995") == HCF_OLDER ||
    hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"4.0.2167.909", bulletin:bulletin, kb:"960995") == HCF_OLDER
  ) {
    set_kb_item(name:"SMB/Missing/MS09-016", value:TRUE);
    hotfix_security_warning();
 }

  hotfix_check_fversion_end();
  exit(0);
}
