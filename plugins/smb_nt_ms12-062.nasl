#
# (C) Tenable Network Security, Inc.
#

include ("compat.inc");

if (description)
{
  script_id(62044);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/23 21:35:42 $");

  script_cve_id("CVE-2012-2536");
  script_bugtraq_id(55430);
  script_osvdb_id(85316);
  script_xref(name:"MSFT", value:"MS12-062");
  script_xref(name:"IAVB", value:"2012-B-0089");

  script_name(english:"MS12-062: Vulnerability in System Center Configuration Manager Could Allow Elevation of Privilege (2741528)");
  script_summary(english:"Checks version of SCCM");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a system management application installed
that is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft System Center Configuration Manager, formerly
known as Systems Management Server, installed on the remote host is
potentially affected by a reflected cross-site scripting vulnerability.
By tricking a user into clicking a specially crafted link, an attacker
could gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-062");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Systems
Management Server 2003 SP3, and Microsoft System Center Configuration
Manager 2007 SP2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:systems_management_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "ms_systems_management_server_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

bulletin = 'MS12-062';
kbs = make_list('2733631', '2721642');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

product = get_kb_item_or_exit('SMB/Microsoft Systems Management Server/Product');
version = get_kb_item_or_exit('SMB/Microsoft Systems Management Server/Version');
if (
  ('Systems Management Server 2003' >!< product && 'System Center Configuration Manager 2007' >!< product) ||
  ('Systems Management Server 2003' >< product && ver_compare(ver:version, fix:'2.50.4253.3000') == -1) ||
  ('System Center Configuration Manager 2007' >< product && (ver_compare(ver:version, fix:'4.0.6487.2000') == -1))
) exit(0, 'The SMS/SCCM installation is not affected based on its version / service pack.');
path = get_kb_item_or_exit('SMB/Microsoft Systems Management Server/Path');

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
path = path + "\bin\i386" + '\\';

if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);
if (
  hotfix_is_vulnerable(path:path, file:'reportinginstall.exe', version:'2.50.4253.3129', min_version:'2.50.4253.3000', bulletin:bulletin, kb:'2733631') ||
  hotfix_is_vulnerable(path:path, file:'reportinginstall.exe', version:'4.0.6487.2209', min_version:'4.0.6487.2000', bulletin:bulletin, kb:'2721642')
)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
