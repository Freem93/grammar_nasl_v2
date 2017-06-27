#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48276);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2010-1797");
  script_bugtraq_id(42241);
  script_osvdb_id(67011);
  script_xref(name:"CERT", value:"275247");
  script_xref(name:"EDB-ID", value:"14538");
  script_xref(name:"Secunia", value:"40903");

  script_name(english:"Foxit Reader < 4.1.1.0805 FreeType CFF Opcodes RCE");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 4.1.1.0805. It is, therefore, affected by a remote code
execution vulnerability in the FreeType engine due to multiple
stack-based buffer overflow conditions in the CFF Type2 CharStrings
interpreter, specifically within the function
cff_decoder_parse_charstrings(). An attacker can exploit this, via
crafted CFF opcodes in embedded fonts in a PDF document, to cause a
denial of service or to execute arbitrary code with the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/weblog/archives/00002002.html");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=194");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 4.1.1.0805 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/08/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

report = NULL;

fixed_version = "4.1.1.0805";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
