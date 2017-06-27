#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91310);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2016-4534");
  script_osvdb_id(138081);
  script_xref(name:"MCAFEE-SB", value:"SB10158");
  script_xref(name:"EDB-ID", value:"39531");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 Patch 6/7 Hotfix 1123565 Protection Bypass Vulnerability (SB10158)");
  script_summary(english:"Checks the version of coptcpl.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus application installed on the remote Windows host is
affected by a security mechanism bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise (VSE) installed on the
remote Windows host is 8.8 Patch 6 or Patch 7 without Hotfix 1123565.
It is, therefore, affected by a flaw related to closing registry
handles for the McAfee VirusScan Console process. A local attacker
with Windows administrative privileges can exploit this flaw to bypass
password protection and thereby unlock the VirusScan Console window,
resulting in access to resources protected by VSE.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10158");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 6/7 Hotfix
1123565.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("Antivirus/McAfee/installed");
product_name = get_kb_item_or_exit("Antivirus/McAfee/product_name");
product_version = get_kb_item_or_exit("Antivirus/McAfee/product_version");

# Since we need to check the coptcpl.dll, we need the path
product_path = get_kb_item_or_exit("Antivirus/McAfee/product_path");

if ("McAfee VirusScan Enterprise" >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

if (product_version !~ "^8\.8\.")
  audit(AUDIT_INST_VER_NOT_VULN, product_name, product_version);

fix = '8.8.0.1546';

# McAfee didn't update the registry for this, so
# we will check coptcpl.dll
dll = product_path+"coptcpl.dll";
ver = hotfix_get_fversion(path:dll);

hotfix_handle_error(error_code:ver['error'],
                    file:dll,
                    appname:"McAfee VirusScan Enterprise",
                    exit_on_fail:TRUE);

hotfix_check_fversion_end();

version = join(sep:".", ver["value"]);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  order  = make_list('File', 'Installed version', 'Fixed version');
  report = make_array(order[0],dll, order[1],version, order[2],fix);
  report = report_items_str(report_items:report, ordered_fields:order);
  security_report_v4(extra:report, port:port, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
