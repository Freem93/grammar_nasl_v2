#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89103);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/26 13:45:01 $");

  script_cve_id(
    "CVE-2016-2521",
    "CVE-2016-2523",
    "CVE-2016-2531",
    "CVE-2016-2532"
  );
  script_osvdb_id(
    131888,
    134834,
    134836,
    135085,
    135086,
    135087,
    135093
  );
  script_xref(name:"EDB-ID", value:"38996");

  script_name(english:"Wireshark 1.12.x < 1.12.10 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.10. It is, therefore, affected by multiple
vulnerabilities in the following components, which can result in a
memory disclosure or a denial of service :

  - ASN.1 BER dissector
  - DNP dissector
  - GSM A-bis OML dissector
  - LLRP dissector
  - RSL dissector

Additionally, a flaw related to how dynamic-link library (DLL) files
are located and loaded exists in the ui/qt/wireshark_application.cpp
file due to the application using a DLL search path that may include
directories that are not trusted or under the user's control. A local
attacker can exploit this issue, via a crafted DLL file injected into
the search path, to execute arbitrary code with the privileges of the
user running the application.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.10.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Wireshark";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

# Affected :
#  1.12.x < 1.12.10
if (version !~ "^1\.12\.[0-9]($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;
  
report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 1.12.10' +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
