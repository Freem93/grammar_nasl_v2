#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92816);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2016-6504",
    "CVE-2016-6505",
    "CVE-2016-6506",
    "CVE-2016-6507",
    "CVE-2016-6508",
    "CVE-2016-6509",
    "CVE-2016-6510",
    "CVE-2016-6511"
  );
  script_bugtraq_id(
    92163,
    92164,
    92165,
    92166,
    92167,
    92168,
    92169,
    92173
  );
  script_osvdb_id(
    142231,
    142232,
    142233,
    142234,
    142235,
    142236,
    142237,
    142238
  );
  script_xref(name:"EDB-ID", value:"40194");
  script_xref(name:"EDB-ID", value:"40197");
  script_xref(name:"EDB-ID", value:"40198");
  script_xref(name:"EDB-ID", value:"40199");

  script_name(english:"Wireshark 1.12.x < 1.12.13 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.13. It is, therefore, affected by multiple denial
of service vulnerabilities :

  - A NULL pointer dereference flaw exists in the
    dissect_nds_request() function in packet-ncp2222.inc due
    to improper handling of packets. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause an
    application crash. (CVE-2016-6504)

  - A denial of service vulnerability exists due to a
    divide-by-zero flaw in the dissect_pbb_tlvblock()
    function in packet-packetbb.c. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted packet or packet trace file, to cause an
    application crash. (CVE-2016-6505)

  - A flaw exists in the add_headers() function in
    packet_wsp.c that is triggered when an offset of zero is
    returned by the wkh_content_disposition() function. An
    unauthenticated, remote attacker can exploit this, via a 
    specially crafted packet or packet trace file, to cause
    an infinite loop, resulting in a denial of service
    condition. (CVE-2016-6506)

  - A flaw exists in the tvb_get_guintvar() function in
    packet-mmse.c that is triggered during the handling of
    an overly large length value. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet or packet trace file, to cause an infinite loop,
    resulting in a denial of service condition.
    (CVE-2016-6507)

  - A denial of service vulnerability exists due to an
    incorrect integer data type used in the rlc_decode_li()
    function in packet-rlc.c. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet or packet trace file, to cause a long loop and
    excessive CPU resource consumption, resulting in a
    denial of service condition. (CVE-2016-6508)

  - A denial of service vulnerability exists in the
    dissect_ldss_transfer() function in packet-ldss.c that
    is triggered when recreating a conversation that already
    exists. An unauthenticated, remote attacker can exploit
    this, via a specially crafted packet or packet trace
    file, to cause an application crash. (CVE-2016-6509)

  - An overflow condition exists in the rlc_decode_li()
    function in packet-rlc.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted packet or
    packet trace file, to cause a stack-based buffer
    overflow, resulting in a denial of service condition.
    (CVE-2016-6510)

  - A denial of service vulnerability exists in the
    proto_tree_add_text_valist_internal() function in
    proto.c due to improper handling of packets. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet or packet trace file, to cause
    a long loop and excessive CPU resource consumption.
    (CVE-2016-6511)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-40.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-41.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-42.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-43.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-44.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-45.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-46.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-47.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.13.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");

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
fix = '1.12.13';

if(version !~ "^1\.12\.")
  exit(0, "The remote installation of Wireshark is not 1.12.x.");

# Affected :
#  1.12.x < 1.12.13
if (version !~ "^1\.12\.([0-9]|1[0-2])($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
