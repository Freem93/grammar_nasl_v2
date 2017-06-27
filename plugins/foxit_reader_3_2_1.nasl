#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45404);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/03/07 16:39:32 $");

  script_cve_id("CVE-2010-1239");
  script_bugtraq_id(39109);
  script_osvdb_id(63548);
  script_xref(name:"Secunia", value:"39291");
  script_xref(name:"CERT", value:"570177");
  script_xref(name:"EDB-ID", value:"11987");

  script_name(english:"Foxit Reader < 3.2.1 Arbitrary Program Execution");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by a command
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 3.2.1. It is, therefore, affected by an arbitrary program
execution vulnerability related to certain '/Type /Action /S /Launch'
or '/Launch /Action' sequences. An attacker can exploit these, by
tricking a user into opening a crafted PDF file, to cause arbitrary
programs to be executed without user permission.");
  script_set_attribute(attribute:"see_also", value:"http://blog.didierstevens.com/2010/03/29/escape-from-pdf/");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=177");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 3.2.1.0401 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/04/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/04/01");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/04/02");
  
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

fixed_version = "3.2.1.0401";
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
