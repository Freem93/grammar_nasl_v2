#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49780);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/03/07 16:39:32 $");

  script_bugtraq_id(43785);
  script_osvdb_id(68648);
  script_xref(name:"Secunia", value:"41656");
  script_xref(name:"EDB-ID", value:"15514");
  script_xref(name:"EDB-ID", value:"15532");
  script_xref(name:"EDB-ID", value:"15542");

  script_name(english:"Foxit Reader < 4.2.0.0928 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 4.2.0.0928. It is, therefore, affected by multiple
vulnerabilities :

  - A stack buffer overflow condition exists due to improper
    sanitization of the file title. An attacker can exploit
    this, via a specially crafted PDF document containing an
    overly long title, to execute arbitrary code.

  - An identity verification vulnerability exists related to
    how digital signatures in a document are validated. An
    attacker can exploit this to falsify documents.");
  script_set_attribute(attribute:"see_also", value:"http://pdfsig-collision.florz.de/");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=200");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 4.2.0.0928 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");

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

fixed_version = "4.2.0.0928";
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
