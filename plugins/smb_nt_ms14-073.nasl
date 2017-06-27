#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79133);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/08 19:36:08 $");

  script_cve_id("CVE-2014-4116");
  script_bugtraq_id(70980);
  script_osvdb_id(114526);
  script_xref(name:"MSFT", value:"MS14-073");
  script_xref(name:"IAVA", value:"2014-A-0175");

  script_name(english:"MS14-073: Vulnerability in Microsoft SharePoint Foundation Could Allow Elevation of Privilege (3000431)");
  script_summary(english:"Checks the version of SharePoint Foundation.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SharePoint Foundation installed on the remote Windows
host is affected by a privilege escalation vulnerability due to the
improper validation of page content in SharePoint lists. By exploiting
this flaw, a remote authenticated attacker can run arbitrary code in
the security context of the logged-on user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/ms14-073.aspx");
  script_set_attribute(attribute:"solution", value:"Microsoft has released patches for SharePoint Foundation 2010 SP2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS14-073";
kb = "2889838";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Get installs of SharePoint
app_name = 'Microsoft SharePoint Server';
get_install_count(app_name:app_name, exit_if_zero:TRUE);
install = get_single_install(app_name:app_name);

path = install['path'];
product = install['Product'];
sp = install['SP'];
version = install['version'];
edition = install['Edition'];

# Only SharePoint Foundation 2010 SP2 is affected
if (
  product != "2010" || 
  (product == "2010" && (sp != "2" || edition != "Foundation"))
) audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

vuln = FALSE;
if (
  hotfix_check_fversion(file:"onetutil.dll", version:"14.0.7137.5000", path:hotfix_append_path(path:path, value:"Bin"), bulletin:bulletin, kb:kb, product:'Microsoft SharePoint Foundation 2010') == HCF_OLDER
) vuln = TRUE;

if (vuln)
{
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
