#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77168);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-2816");
  script_bugtraq_id(69099);
  script_osvdb_id(109941);
  script_xref(name:"MSFT", value:"MS14-050");
  script_xref(name:"IAVA", value:"2014-A-0125");

  script_name(english:"MS14-050: Vulnerability in Microsoft SharePoint Server Could Allow Elevation of Privilege (2977202)");
  script_summary(english:"Checks the SharePoint version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft SharePoint Server installed on the remote
host is affected by an elevation of privilege vulnerability that
allows cross-site scripting. An authenticated attacker could exploit
this vulnerability to execute arbitrary JavaScript in the context of
the user's browser.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-050");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for SharePoint Server 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_sharepoint_installed.nbin", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS14-050";
kbs = make_list(
  2880994
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get installs of SharePoint.
app_name = 'Microsoft SharePoint Server';
get_install_count(app_name:app_name, exit_if_zero:TRUE);
install = get_single_install(app_name:app_name);

path = install['path'];
product = install['Product'];
sp = install['SP'];
version = install['version'];
vuln = FALSE;

# Only 2013 & 2013 SP1 are affected.
if (product != "2013" || !(sp == '0' || sp == '1'))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Get path information for Common Files.
common_files = hotfix_get_commonfilesdir();
if (isnull(common_files))
  exit(1, "Failed to determine the location of %commonprogramfiles%.");

if (
   hotfix_check_fversion(
    file:"CsiSrv.dll",
    version:"15.0.4641.1000",
    path:hotfix_append_path(path:common_files, value:"Microsoft Shared\Web Server Extensions\15\BIN\"),
    bulletin:bulletin,
    kb:"2880994",
    product:app_name) == HCF_OLDER
  )
  vuln = TRUE;

if (vuln)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
