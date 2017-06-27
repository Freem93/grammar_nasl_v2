#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93518);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2016-7175",
    "CVE-2016-7176",
    "CVE-2016-7177",
    "CVE-2016-7178",
    "CVE-2016-7179",
    "CVE-2016-7180"
  );
  script_bugtraq_id(92889);
  script_osvdb_id(
    144012,
    143972,
    143973,
    143974,
    143975,
    143976
  );

  script_name(english:"Wireshark 2.0.x < 2.0.6 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.6. It is, therefore, affected by multiple denial of
service vulnerabilities :

  - A flaw exists in the QNX6 QNET dissector in the
    dissect_qnet6_lr() function in packet-qnet6.c due to
    improper handling of MAC address data. An
    unauthenticated, remote attacker can exploit this, via a
    crafted packet, to crash the program, resulting in a
    denial of service. (CVE-2016-7175)

  - Multiple flaws exist in the H.225 dissector in
    packet-h225.c due to improper handling of strings in
    malformed packets. An unauthenticated, remote attacker
    can exploit this, via a crafted packet, to crash the
    program, resulting in a denial of service.
    (CVE-2016-7176)

  - An out-of-bounds read error exists in the Catapult
    DCT2000 dissector in the attach_fp_info() function in
    packet-catapult-dct2000.c due to a failure to restrict
    the number of channels. An unauthenticated, remote
    attacker can exploit this, via a crafted packet, to
    crash the program, resulting in a denial of service.
    (CVE-2016-7177)

  - A NULL pointer dereference flaw exists in the UMTS FP
    dissector in packet-umts_fp.c due to a failure to ensure
    that memory is allocated for certain data structures. An
    unauthenticated, remote attacker can exploit this, via a
    crafted packet, to crash the program, resulting in a
    denial of service. (CVE-2016-7178)

  - A stack-based buffer overflow condition exists in the
    Catapult DCT2000 dissector in the parse_outhdr_string()
    function in packet-catapult-dct2000.c due to improper
    validation of specially crafted packets. An
    unauthenticated, remote attacker can exploit this, via a
    crafted packet, to crash the program, resulting in a
    denial of service. (CVE-2016-7179)

  - A flaw exists in the IPMI Trace dissector in the
    dissect_ipmi_trace() function in packet-ipmi-trace.c due
    to a failure to properly consider whether a string is
    constant. An unauthenticated, remote attacker can
    exploit this, via a crafted packet, to crash the
    program, resulting in a denial of service.
    (CVE-2016-7180)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-50.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-51.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-52.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-53.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-54.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-55.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.6.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

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
fix = '2.0.6';

if(version !~ "^2\.0\.")
  exit(0, "The remote installation of Wireshark is not 2.0.x.");

# Affected :
#  2.0.x < 2.0.6
if (version !~ "^2\.0\.[0-5]($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
