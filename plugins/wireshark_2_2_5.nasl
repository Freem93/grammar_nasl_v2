#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97574);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/21 16:53:28 $");

  script_cve_id(
    "CVE-2017-6467",
    "CVE-2017-6468",
    "CVE-2017-6469",
    "CVE-2017-6470",
    "CVE-2017-6471",
    "CVE-2017-6472",
    "CVE-2017-6473",
    "CVE-2017-6474"
  );
  script_osvdb_id(
    152953,
    152954,
    152957,
    152958,
    152963,
    152964,
    152967,
    152969
  );

  script_name(english:"Wireshark 2.0.x < 2.0.11 / 2.2.x < 2.2.5 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.11 or 2.2.x prior to 2.2.5. It is, therefore, affected by
multiple denial of service vulnerabilities :

  - An infinite loop condition exists in the Netscaler file
    parser in the nstrace_read_v20() and nstrace_read_v30()
    functions within file wiretap/netscaler.c due to
    improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted capture file, to consume excessive
    memory resources, resulting in a denial of service
    condition. (CVE-2017-6467)

  - An out-of-bounds read error exists within various
    functions in file wiretap/netscaler.c when handling
    record lengths. An unauthenticated, remote attacker can
    exploit this, via a specially crafted capture file, to
    crash the Netscaler file parser process. (CVE-2017-6468)

  - A memory allocation issue exists in the
    dissect_ldss_transfer() function within file
    epan/dissectors/packet-ldss.c due to improper validation
    of certain input. An unauthenticated, remote attacker
    can exploit this, via packet injection or a specially
    crafted capture file, to crash the LDSS dissector
    process. (CVE-2017-6469)

  - An infinite loop condition exists in IAX2 in the
    iax2_add_ts_fields() function within file
    epan/dissectors/packet-iax2.c when processing
    timestamps. An unauthenticated, remote attacker can
    exploit this, via packet injection or a specially
    crafted capture file, to consume excessive CPU
    resources, resulting in a denial of service condition.
    (CVE-2017-6470)

  - An infinite loop condition exists in WSP in the
    dissect_wsp_common() function within file
    epan/dissectors/packet-wsp.c when handling capability
    lengths. An unauthenticated, remote attacker can exploit
    this, via packet injection or a specially crafted
    capture file, to cause a denial of service condition.
    (CVE-2017-6471)

  - An infinite loop condition exists in the RTMPT dissector
    in the dissect_rtmpt_common() function within file
    epan/dissectors/packet-rtmpt.c due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this, via packet injection or a
    specially crafted capture file, to consume excessive
    memory resources, resulting in a denial of service
    condition. (CVE-2017-6472)

  - A denial of service vulnerability exists in the
    process_packet_data() function within file wiretap/k12.c
    due to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted capture file, to crash the K12 file
    parser process. (CVE-2017-6473)

  - An infinite loop condition exists in the NetScaler file
    parser in the nstrace_read_v10(), nstrace_read_v20(),
    and nstrace_read_v30() functions within file
    wiretap/netscaler.c when handling record sizes. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted capture file, to consume excessive
    memory resources, resulting in a denial of service
    condition. (CVE-2017-6474)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-03.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-04.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-05.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-07.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-08.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-09.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-11.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.11 / 2.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
fix = NULL;
min = NULL;
flag = 0;

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (version =~ "^2\.0\.")
{
  fix = "2.0.11";
  min = "2.0.0";
  flag++;
}

if (version =~ "^2\.2\.")
{
  fix = "2.2.5";
  min = "2.2.0";
  flag++;
}

if (flag && ver_compare(ver:version, fix:fix, minver:min, strict:FALSE) <  0 )
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else
{
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
}
