#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62384);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/07 16:39:32 $");

  script_bugtraq_id(55686);
  script_osvdb_id(85774);
  script_xref(name:"Secunia", value:"50526");

  script_name(english:"Foxit Reader < 5.4.3 Trojan DLL Injection");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by an arbitrary
code execution vulnerability.");
  script_set_attribute(attribute:"description",  value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 5.4.3. It is, therefore, affected by a flaw in how
dynamic-link library (DLL) files are located and loaded, specifically
file fxdecod1.dll. The application uses a fixed path to search for
this file, and the path can include directories that may not be
trusted or under the user's control. A local attacker can exploit this
issue, via a crafted Trojan horse DLL file injected into the search
path, to execute arbitrary code with the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution",  value:
"Upgrade to Foxit Reader version 5.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

fixed_version = "5.4.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
