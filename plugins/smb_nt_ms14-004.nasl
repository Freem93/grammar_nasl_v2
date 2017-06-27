#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(71944);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-0261");
  script_bugtraq_id(64724);
  script_osvdb_id(101977);
  script_xref(name:"MSFT", value:"MS14-004");
  script_xref(name:"IAVB", value:"2014-B-0005");

  script_name(english:"MS14-004: Vulnerability in Microsoft Dynamics AX Could Allow Denial of Service (2880826)");
  script_summary(english:"Checks version of AxPerf.dll or Microsoft.dynamics.ax.managedinterop.dll");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Dynamics AX installed on the remote host has a
denial of service vulnerability in the Application Object Server
instance.  By exploiting this flaw, a remote, authenticated attacker
could crash the affected service.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-004");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Dynamics AX 4.0, Dynamics
AX 2009, Dynamics AX 2012, and Dynamics AX 2012 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_ax");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_dynamics_ax_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS14-004';
kbs = make_list('2914055', '2914057', '2914058', '2920510');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

path = get_kb_item_or_exit('SMB/microsoft_dynamics_ax/path');
ver = get_kb_item_or_exit('SMB/microsoft_dynamics_ax/ver');

# nb: Dynamics AX 2012 and 2012 R2 both show up as 6.0.
if (ver != '4.0' && ver != '5.0' && ver != '6.0' ) audit(AUDIT_INST_VER_NOT_VULN, 'Dynamics AX', ver);

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

vuln += hotfix_is_vulnerable(file:"AxPerf.dll", version:"4.0.2503.1872", min_version:"4.0.2501.116", path:path + "\Server\Common", bulletin:bulletin, kb:'2920510');
vuln += hotfix_is_vulnerable(file:"AxPerf.dll", version:"5.0.1600.2390", min_version:"5.0.1000.52", path:path + "\Server\Common", bulletin:bulletin, kb:'2914058');
vuln += hotfix_is_vulnerable(file:"Microsoft.dynamics.ax.managedinterop.dll", version:"6.0.1108.6134", min_version:"6.0.0.0", path:path + "\Server\MicrosoftDynamicsAX\bin", bulletin:bulletin, kb:'2914055');
vuln += hotfix_is_vulnerable(file:"Microsoft.dynamics.ax.managedinterop.dll", version:"6.2.1000.5419", min_version:"6.2.158.0", path:path + "\Server\MicrosoftDynamicsAX\bin", bulletin:bulletin, kb:'2914057');

if (vuln > 0)
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
