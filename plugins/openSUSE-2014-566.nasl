#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-566.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(78021);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/21 15:59:35 $");

  script_cve_id("CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165", "CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2014:1249-1)");
  script_summary(english:"Check for the openSUSE-2014-566 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was update to 1.10.10 [bnc#897055]

On openSUSE 12.3, the package was upgraded to 1.10.x from 1.8.x as it
was discontinued.

This update fixes vulnerabilities in Wireshark that could allow an
attacker to crash Wireshark or make it become unresponsive by sending
specific packages onto the network or have it loaded via a capture
file while the dissectors are running. It also contains a number of
other bug fixes.

  - RTP dissector crash wnpa-sec-2014-12 CVE-2014-6421
    CVE-2014-6422

  - MEGACO dissector infinite loop wnpa-sec-2014-13
    CVE-2014-6423

  - Netflow dissector crash wnpa-sec-2014-14 CVE-2014-6424

  - RTSP dissector crash wnpa-sec-2014-17 CVE-2014-6427

  - SES dissector crash wnpa-sec-2014-18 CVE-2014-6428

  - Sniffer file parser crash wnpa-sec-2014-19 CVE-2014-6429
    CVE-2014-6430 CVE-2014-6431 CVE-2014-6432

  - Further bug fixes as listed in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.10.1
    0.html

  - includes changes from 1.10.9: fixes several crashes
    triggered by malformed protocol packages

  - vulnerabilities fixed :

  - The Catapult DCT2000 and IrDA dissectors could underrun
    a buffer wnpa-sec-2014-08 CVE-2014-5161 CVE-2014-5162
    (bnc#889901)

  - The GSM Management dissector could crash
    wnpa-sec-2014-09 CVE-2014-5163 (bnc#889906)

  - The RLC dissector could crash wnpa-sec-2014-10
    CVE-2014-5164 (bnc#889900)

  - The ASN.1 BER dissector could crash wnpa-sec-2014-11
    CVE-2014-5165 (bnc#889899)

  - Further bug fixes as listed in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.10.9
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00058.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.9.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"wireshark-1.10.10-1.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debuginfo-1.10.10-1.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debugsource-1.10.10-1.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-devel-1.10.10-1.44.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-1.10.10-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debuginfo-1.10.10-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debugsource-1.10.10-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-devel-1.10.10-24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
