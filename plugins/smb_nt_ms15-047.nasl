#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83357);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2015-1700");
  script_bugtraq_id(74480);
  script_osvdb_id(122007);
  script_xref(name:"MSFT", value:"MS15-047");
  script_xref(name:"IAVA", value:"2015-A-0104");

  script_name(english:"MS15-047: Vulnerabilities in Microsoft SharePoint Server Could Allow Remote Code Execution (3058083)");
  script_summary(english:"Checks the SharePoint version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft SharePoint Server
that is affected by a remote code execution vulnerability due to not
properly sanitizing specially crafted page content. An authenticated,
remote attacker, by sending a malicious page to a SharePoint server,
can exploit this to run arbitrary code in the security context of the
W3WP service account.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-047");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2007,
2010, and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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


bulletin = 'MS15-047';
kbs = make_list(
  2760412, # SharePoint 2007 SP3
  2956192, # SharePoint Server 2010
  3017815, # SharePoint Foundation 2010
  3054792  # SharePoint Server 2013
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = 'Microsoft SharePoint Server';
get_install_count(app_name:app_name, exit_if_zero:TRUE);
install = get_single_install(app_name:app_name);

path = install['path'];
version = install['version'];
edition = NULL;
if (!empty_or_null(install['Edition'])) edition = install['Edition'];
sp = NULL;
if (!empty_or_null(install['SP'])) sp = int(install['SP']);
product = app_name;
if (!empty_or_null(install['Product'])) product = app_name + ' ' + install['Product'];
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

common_files = hotfix_get_commonfilesdir();
if (isnull(common_files))
  exit(1, "Failed to determine the location of %commonprogramfiles%.");

if (version =~ '^12\\.')
{
  if ((!isnull(edition) && 'Server' >< edition) && (!isnull(sp) && sp == 3))
  {
    if (hotfix_check_fversion(file:'Microsoft.SharePoint.Portal.dll', version:'12.0.6721.5000', path:hotfix_append_path(path:windir, value:"assembly\GAC_MSIL\Microsoft.SharePoint.Portal\12.0.0.0__71e9bce111e9429c"), bulletin:bulletin, kb:'2760412', product:product) == HCF_OLDER)
      vuln = TRUE;
  }
}
else if (version =~ '^14\\.')
{
  if (!isnull(sp) && sp == 2)
  {
    if (!isnull(edition))
    {
      if ('Foundation' >< edition)
      {
        if (hotfix_check_fversion(file:'Onetutil.dll', version:'14.0.7149.5000', path:hotfix_append_path(path:path, value:"Bin"), bulletin:bulletin, kb:'3017815', product:product) == HCF_OLDER)
          vuln = TRUE;
      }
      else if ('Server' >< edition)
      {
        if (hotfix_check_fversion(file:'Microsoft.SharePoint.Portal.dll', version:'14.0.7149.5000', path:hotfix_append_path(path:windir, value:"assembly\GAC_MSIL\Microsoft.SharePoint.Portal\14.0.0.0__71e9bce111e9429c"), bulletin:bulletin, kb:'2956192', product:product) == HCF_OLDER)
          vuln = TRUE;
      }
    }
  }
}
else if (version =~ '^15\\.')
{
  if (!isnull(edition) && 'Foundation' >< edition)
  {
    if (!isnull(sp) && sp == 1)
    {
      if (hotfix_check_fversion(file:'CsiSrv.dll', version:'15.0.4709.1000', path:hotfix_append_path(path:common_files, value:"Microsoft Shared\Web Server Extensions\15\BIN\"), bulletin:bulletin, kb:'3054792', product:product) == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
