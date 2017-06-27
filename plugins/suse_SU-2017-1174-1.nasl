#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1174-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(99991);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/08 14:04:54 $");

  script_cve_id("CVE-2016-7175", "CVE-2016-7176", "CVE-2016-7177", "CVE-2016-7178", "CVE-2016-7179", "CVE-2016-7180", "CVE-2016-9373", "CVE-2016-9374", "CVE-2016-9375", "CVE-2016-9376", "CVE-2017-5596", "CVE-2017-5597", "CVE-2017-6014", "CVE-2017-7700", "CVE-2017-7701", "CVE-2017-7702", "CVE-2017-7703", "CVE-2017-7704", "CVE-2017-7705", "CVE-2017-7745", "CVE-2017-7746", "CVE-2017-7747", "CVE-2017-7748");
  script_osvdb_id(143972, 143973, 143974, 143975, 143976, 144012, 147426, 147427, 147428, 147429, 150784, 150785, 152218, 155467, 155468, 155471, 155472, 155473, 155474, 155475, 155476, 155477, 155478);
  script_xref(name:"IAVB", value:"2017-B-0046");

  script_name(english:"SUSE SLES11 Security Update : wireshark (SUSE-SU-2017:1174-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to version 2.0.12, which brings several new
features, enhancements and bug fixes. These security issues were 
fixed :

  - CVE-2017-7700: In Wireshark the NetScaler file parser
    could go into an infinite loop, triggered by a malformed
    capture file. This was addressed in wiretap/netscaler.c
    by ensuring a nonzero record size (bsc#1033936).

  - CVE-2017-7701: In Wireshark the BGP dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-bgp.c by using a different
    integer data type (bsc#1033937).

  - CVE-2017-7702: In Wireshark the WBXML dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-wbxml.c by adding length
    validation (bsc#1033938).

  - CVE-2017-7703: In Wireshark the IMAP dissector could
    crash, triggered by packet injection or a malformed
    capture file. This was addressed in
    epan/dissectors/packet-imap.c by calculating a line's
    end correctly (bsc#1033939).

  - CVE-2017-7704: In Wireshark the DOF dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-dof.c by using a different
    integer data type and adjusting a return value
    (bsc#1033940).

  - CVE-2017-7705: In Wireshark the RPC over RDMA dissector
    could go into an infinite loop, triggered by packet
    injection or a malformed capture file. This was
    addressed in epan/dissectors/packet-rpcrdma.c by
    correctly checking for going beyond the maximum offset
    (bsc#1033941).

  - CVE-2017-7745: In Wireshark the SIGCOMP dissector could
    go into an infinite loop, triggered by packet injection
    or a malformed capture file. This was addressed in
    epan/dissectors/packet-sigcomp.c by correcting a
    memory-size check (bsc#1033942).

  - CVE-2017-7746: In Wireshark the SLSK dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-slsk.c by adding checks for the
    remaining length (bsc#1033943).

  - CVE-2017-7747: In Wireshark the PacketBB dissector could
    crash, triggered by packet injection or a malformed
    capture file. This was addressed in
    epan/dissectors/packet-packetbb.c by restricting
    additions to the protocol tree (bsc#1033944).

  - CVE-2017-7748: In Wireshark the WSP dissector could go
    into an infinite loop, triggered by packet injection or
    a malformed capture file. This was addressed in
    epan/dissectors/packet-wsp.c by adding a length check
    (bsc#1033945).

  - CVE-2016-7179: Stack-based buffer overflow in
    epan/dissectors/packet-catapult-dct2000.c in the
    Catapult DCT2000 dissector in Wireshark allowed remote
    attackers to cause a denial of service (application
    crash) via a crafted packet (bsc#998963).

  - CVE-2016-9376: In Wireshark the OpenFlow dissector could
    crash with memory exhaustion, triggered by network
    traffic or a capture file. This was addressed in
    epan/dissectors/packet-openflow_v5.c by ensuring that
    certain length values were sufficiently large
    (bsc#1010735).

  - CVE-2016-9375: In Wireshark the DTN dissector could go
    into an infinite loop, triggered by network traffic or a
    capture file. This was addressed in
    epan/dissectors/packet-dtn.c by checking whether SDNV
    evaluation was successful (bsc#1010740).

  - CVE-2016-9374: In Wireshark the AllJoyn dissector could
    crash with a buffer over-read, triggered by network
    traffic or a capture file. This was addressed in
    epan/dissectors/packet-alljoyn.c by ensuring that a
    length variable properly tracked the state of a
    signature variable (bsc#1010752).

  - CVE-2016-9373: In Wireshark the DCERPC dissector could
    crash with a use-after-free, triggered by network
    traffic or a capture file. This was addressed in
    epan/dissectors/packet-dcerpc-nt.c and
    epan/dissectors/packet-dcerpc-spoolss.c by using the
    wmem file scope for private strings (bsc#1010754).

  - CVE-2016-7175: epan/dissectors/packet-qnet6.c in the
    QNX6 QNET dissector in Wireshark mishandled MAC address
    data, which allowed remote attackers to cause a denial
    of service (out-of-bounds read and application crash)
    via a crafted packet (bsc#998761).

  - CVE-2016-7176: epan/dissectors/packet-h225.c in the
    H.225 dissector in Wireshark called snprintf with one of
    its input buffers as the output buffer, which allowed
    remote attackers to cause a denial of service (copy
    overlap and application crash) via a crafted packet
    (bsc#998762).

  - CVE-2016-7177: epan/dissectors/packet-catapult-dct2000.c
    in the Catapult DCT2000 dissector in Wireshark did not
    restrict the number of channels, which allowed remote
    attackers to cause a denial of service (buffer over-read
    and application crash) via a crafted packet
    (bsc#998763).

  - CVE-2016-7180: epan/dissectors/packet-ipmi-trace.c in
    the IPMI trace dissector in Wireshark did not properly
    consider whether a string is constant, which allowed
    remote attackers to cause a denial of service
    (use-after-free and application crash) via a crafted
    packet (bsc#998800).

  - CVE-2016-7178: epan/dissectors/packet-umts_fp.c in the
    UMTS FP dissector in Wireshark did not ensure that
    memory is allocated for certain data structures, which
    allowed remote attackers to cause a denial of service
    (invalid write access and application crash) via a
    crafted packet (bsc#998964).

  - CVE-2017-6014: In Wireshark a crafted or malformed
    STANAG 4607 capture file will cause an infinite loop and
    memory exhaustion. If the packet size field in a packet
    header is null, the offset to read from will not
    advance, causing continuous attempts to read the same
    zero length packet. This will quickly exhaust all system
    memory (bsc#1025913).

  - CVE-2017-5596: In Wireshark the ASTERIX dissector could
    go into an infinite loop, triggered by packet injection
    or a malformed capture file. This was addressed in
    epan/dissectors/packet-asterix.c by changing a data type
    to avoid an integer overflow (bsc#1021739).

  - CVE-2017-5597: In Wireshark the DHCPv6 dissector could
    go into a large loop, triggered by packet injection or a
    malformed capture file. This was addressed in
    epan/dissectors/packet-dhcpv6.c by changing a data type
    to avoid an integer overflow (bsc#1021739).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9373.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9374.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9376.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7700.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7701.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7703.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7746.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7747.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7748.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171174-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa394455"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-wireshark-13089=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-wireshark-13089=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-wireshark-13089=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/05");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-2.0.12-36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-gtk-2.0.12-36.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
