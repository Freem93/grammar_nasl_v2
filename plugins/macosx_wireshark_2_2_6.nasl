#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99436);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/20 15:44:21 $");

  script_cve_id(
    "CVE-2017-7700",
    "CVE-2017-7701",
    "CVE-2017-7702",
    "CVE-2017-7703",
    "CVE-2017-7704",
    "CVE-2017-7705",
    "CVE-2017-7745",
    "CVE-2017-7746",
    "CVE-2017-7747",
    "CVE-2017-7748"
  );
  script_bugtraq_id(
    97627,
    97628,
    97630,
    97631,
    97632,
    97633,
    97634,
    97635,
    97636,
    97638
  );
  script_osvdb_id(
    155467,
    155468,
    155471,
    155472,
    155473,
    155474,
    155475,
    155476,
    155477,
    155478
  );
   script_xref(name:"IAVB", value:"2017-B-0046");

  script_name(english:"Wireshark 2.0.x < 2.0.12 / 2.2.x < 2.2.6 Multiple DoS (macOS)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS or Mac OS X
host is 2.0.x prior to 2.0.12 or 2.2.x prior to 2.2.6. It is,
therefore, affected by multiple denial of service vulnerabilities :

  - An infinite loop condition condition exists in the
    NetScaler file parser within file wiretap/netscaler.c
    when handling specially crafted capture files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7700)

  - An infinite loop condition condition exists in the BGP
    dissector within file epan/dissectors/packet-bgp.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7701)

  - An infinite loop condition condition exists in the WBXML
    dissector within file epan/dissectors/packet-wbxml.c
    when handling specially crafted packets or trace files.
    An unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7702)

  - An denial of service vulnerability exists in the IMAP
    dissector within file epan/dissectors/packet-imap.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    crash the program. (CVE-2017-7703)

  - An infinite loop condition condition exists in the DOF
    dissector within file epan/dissectors/packet-dof.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. Note that this issue
    only applies to the 2.2.x version. (CVE-2017-7704)

  - An infinite loop condition condition exists in the RPC
    over RDMA dissector within file
    epan/dissectors/packet-rpcrdma.c when handling specially
    crafted packets or trace files. An unauthenticated,
    remote attacker can exploit this to cause excessive
    consumption of CPU resources, resulting in a denial of
    service condition. (CVE-2017-7705)

  - An infinite loop condition condition exists in the
    SIGCOMP dissector within file
    epan/dissectors/packet-sigcomp.c when handling specially
    crafted packets or trace files. An unauthenticated,
    remote attacker can exploit this to cause excessive
    consumption of CPU resources, resulting in a denial of
    service condition. (CVE-2017-7745)

  - An infinite loop condition condition exists in the
    SLSK dissector in the dissect_slsk_pdu() function within
    file epan/dissectors/packet-slsk.c, when handling
    specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7746)

  - An out-of-bounds read error exists in the PacketBB
    dissector in the dissect_pbb_addressblock() function
    within file epan/dissectors/packet-packetbb.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    crash the program. (CVE-2017-7747)

  - An infinite loop condition condition exists in the WSP
    dissector within file epan/dissectors/packet-wsp.c when
    handling specially crafted packets or trace files. An
    unauthenticated, remote attacker can exploit this to
    cause excessive consumption of CPU resources, resulting
    in a denial of service condition. (CVE-2017-7748)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.6.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-21.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.12 / 2.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/18");


  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

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
fix = NULL;
min = NULL;
flag = 0;

if (version =~ "^2\.0\.")
{
  fix = "2.0.12";
  min = "2.0.0";
  flag++;
}

if (version =~ "^2\.2\.")
{
  fix = "2.2.6";
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

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
