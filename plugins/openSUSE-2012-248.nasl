#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-248.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74610);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-1593", "CVE-2012-1595", "CVE-2012-1596");
  script_osvdb_id(80711, 80713, 80714);

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2012:0558-1)");
  script_summary(english:"Check for the openSUSE-2012-248 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in wireshark :

  - update to 1.4.12

  - fix bnc#754474, bnc#754476, bnc#754477(fixed upstream)

  - Security fixes :

  - wnpa-sec-2012-04 The ANSI A dissector could dereference
    a NULL pointer and crash. (Bug 6823)

  - wnpa-sec-2012-06 The pcap and pcap-ng file parsers could
    crash trying to read ERF data. (Bug 6804)

  - wnpa-sec-2012-07 The MP2T dissector could try to
    allocate too much memory and crash. (Bug 6804)

  - The Windows installers now include GnuTLS 1.12.18, which
    fixes several vulnerabilities.

  - Bug fixes :

  - Some PGM options are not parsed correctly. (Bug 5687)

  - dumpcap crashes when capturing from pipe to a pcap-ng
    file (e.g., when passing data from CACE Pilot to
    Wireshark). (Bug 5939)

  - No error for UDP/IPv6 packet with zero checksum. (Bug
    6232)

  - packetBB dissector bug: More than 1000000 items in the
    tree -- possible infinite loop. (Bug 6687)

  - Ethernet traces in K12 text format sometimes give bogus
    'malformed frame' errors and other problems. (Bug 6735)

  - non-IPP packets to or from port 631 are dissected as
    IPP. (Bug 6765)

  - IAX2 dissector reads past end of packet for unknown IEs.
    (Bug 6815)

  - Pcap-NG files with SHB options longer than 100 bytes
    aren't recognized as pcap-NG files, and options longer
    than 100 bytes in other blocks aren't handled either.
    (Bug 6846)

  - Patch to fix DTLS decryption. (Bug 6847)

  - Expression... dialog is crash. (Bug 6891)

  - ISAKMP : VendorID CheckPoint : Malformed Packet. (Bug
    6972)

  - Radiotap dissector lists a bogus 'DBM TX Attenuation'
    bit. (Bug 7000)

  - MySQL dissector assertion. (Ask 8649) Updated Protocol
    Support HTTP, ISAKMP, MySQL, PacketBB, PGM, TCP, UDP New
    and Updated Capture File Support Endace ERF, Pcap-NG."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-04/msg00060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754477"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"wireshark-1.4.12-0.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wireshark-debuginfo-1.4.12-0.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wireshark-debugsource-1.4.12-0.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wireshark-devel-1.4.12-0.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-1.4.12-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debuginfo-1.4.12-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debugsource-1.4.12-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-devel-1.4.12-3.8.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
