#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89102);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/26 13:45:01 $");

  script_cve_id(
    "CVE-2016-2521",
    "CVE-2016-2522",
    "CVE-2016-2523",
    "CVE-2016-2524",
    "CVE-2016-2525",
    "CVE-2016-2526",
    "CVE-2016-2527",
    "CVE-2016-2528",
    "CVE-2016-2529",
    "CVE-2016-2530",
    "CVE-2016-2531",
    "CVE-2016-2532"
  );
  script_osvdb_id(
    131888,
    133670,
    133675,
    133676,
    133677,
    133678,
    134834,
    134835,
    134836,
    134902,
    135085,
    135086,
    135087,
    135089,
    135090,
    135091,
    135092,
    135093
  );
  script_xref(name:"EDB-ID", value:"38996");
  script_xref(name:"EDB-ID", value:"39490");

  script_name(english:"Wireshark 2.0.x < 2.0.2 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Mac OS X host is
2.0.x prior to 2.0.2. It is, therefore, affected by multiple
vulnerabilities in the following components, which can result in a
memory disclosure, a denial of service, or the execution of arbitrary
code :

  - 3GPP TS 32.423 Trace file parser
  - ASN.1 BER dissector
  - DNP dissector
  - GSM A-bis OML dissector
  - HiQnet dissector
  - HTTP/2 dissector
  - IEEE 802.11 dissector
  - iSeries file parser
  - Ixia IxVeriWave file parser
  - LBMC dissector
  - LLRP dissector
  - NFS dissector
  - RSL dissector
  - SPICE dissector
  - X.509AF dissector

Additionally, a flaw related to how dynamic-link library (DLL) files
are located and loaded exists in the ui/qt/wireshark_application.cpp
file due to the application using a DLL search path that may include
directories that are not trusted or under the user's control. A local
attacker can exploit this issue, via a crafted DLL file injected into
the search path, to execute arbitrary code with the privileges of the
user running the application.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
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
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit("Host/MacOSX/Version");

app_name = "Wireshark";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = "2.0.2";

# Affected :
#  2.0.x < 2.0.2
if (version !~ "^2\.0\.[01]($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fixed_version +
  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
