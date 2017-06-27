#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32396);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/03/07 16:39:32 $");

  script_cve_id("CVE-2008-1104");
  script_bugtraq_id(29288);
  script_osvdb_id(45351);
  script_xref(name:"Secunia", value:"29941");
  script_xref(name:"CERT", value:"119747");

  script_name(english:"Foxit Reader < 2.3 Build 2923 util.printf() Floating Point Specifier RCE");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 2.3 Build 2923. It is, therefore, affected by a boundary
error that is triggered when parsing format strings containing a
floating point specifier in the util.printf() JavaScript function. An
attacker can exploit this issue, by tricking a user into opening a
crafted PDF file, to execute arbitrary code with the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-18/advisory/");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 2.3 Build 2923 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value: "2008/05/20");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Foxit Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];

# Remove the year from the version where applicable
ver_ui = NULL;
if (ereg(pattern:"200[789]\.", string:version))
{
  ver_ui = version;
  version = ereg_replace(pattern:"(200[789]\.)", replace:"", string:version);
}

report = NULL;

fixed_version = "2.3.2923";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report = '\n  Path              : ' + path;

  if (!isnull(ver_ui))
    report += '\n  UI version        : ' + ver_ui;

  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
