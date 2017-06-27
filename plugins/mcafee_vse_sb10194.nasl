#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100125);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/11 21:47:37 $");

  script_cve_id("CVE-2016-8030");
  script_bugtraq_id(98041);
  script_osvdb_id(155409);
  script_xref(name:"MCAFEE-SB", value:"SB10194");
  script_xref(name:"IAVA", value:"2017-A-0136");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 Patch 9 Scriptscan COM Object DoS (SB10194)");
  script_summary(english:"Checks the version of coptcpl.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus application installed on the remote Windows host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise (VSE) installed on the
remote Windows host is prior to 8.9 Patch 9. It is, therefore,
affected by a memory corruption issue in the Scriptscan COM object. An
unauthenticated, remote attacker can exploit this, via a specially
crafted HTML link, to cause a denial of service condition on the
active Internet Explorer tab. Note that this denial of service occurs
only after a fresh installation of the Scriptscan COM DLL during
initialization.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10194");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

product_path = get_kb_item_or_exit("Antivirus/McAfee/product_path");
app = "McAfee VirusScan Enterprise";

if (app >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

if (product_version !~ "^8\.8\.")
  audit(AUDIT_INST_VER_NOT_VULN, product_name, product_version);

fix = '8.8.0.1804';

# Check coptcpl.dll version
dll = product_path+"coptcpl.dll";
ver = hotfix_get_fversion(path:dll);

hotfix_handle_error(error_code:ver['error'],
                    file:dll,
                    appname:app,
                    exit_on_fail:TRUE);

hotfix_check_fversion_end();

version = join(sep:".", ver["value"]);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  order  = make_list('File', 'Installed version', 'Fixed version');
  report = make_array(order[0],dll, order[1],version, order[2],fix);
  report = report_items_str(report_items:report, ordered_fields:order);
  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
