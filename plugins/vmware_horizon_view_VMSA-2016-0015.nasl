#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94053);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id("CVE-2016-7087");
  script_bugtraq_id(93455);
  script_osvdb_id(145235);
  script_xref(name:"VMSA", value:"2016-0015");

  script_name(english:"VMware Horizon View Directory Traversal File Disclosure (VMSA-2016-0015)");
  script_summary(english:"Checks the version of VMware Horizon View.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an
information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View installed on the remote Windows
host is 5.x prior to 5.3.7, 6.x prior to 6.2.3, or 7.x prior to 7.0.1.
It is, therefore, affected by an information disclosure vulnerability
in the loadConfig() function within the loggerBean service due to
improper sanitization of user-supplied input. An unauthenticated,
remote attacker can exploit this, via a specially crafted request, to
perform a directory traversal and thereby disclose the contents of
arbitrary files.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0015.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View version 5.3.7 / 6.2.3 / 7.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_view_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "VMware Horizon View";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path     = install['path'];
version  = install['version'];

if (version =~ "^5([^0-9]|$)")
  fix = "5.3.7";
else if (version =~ "^6([^0-9]|$)")
  fix = "6.2.3";
else if (version =~ "^7([^0-9]|$)")
  fix = "7.0.1";
else
  audit(AUDIT_NOT_INST, app_name + " 5.x, 6.x, or 7.x");

if (
  version =~ "^5(\.3)?$"
  ||
  version =~ "^6(\.2)?$"
  ||
  version =~ "^7(\.0)?$"
)
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
