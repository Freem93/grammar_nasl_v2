#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-226.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81869);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:34 $");

  script_cve_id("CVE-2015-2187", "CVE-2015-2188", "CVE-2015-2189", "CVE-2015-2190", "CVE-2015-2191", "CVE-2015-2192");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2015-226)");
  script_summary(english:"Check for the openSUSE-2015-226 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to 1.10.13 on openSUSE 13.1 to fix bugs and
security issues. Wireshark was updated to 1.12.4 on openSUSE 13.2 to
fix bugs and security issues.

The following security issues were fixed in 1.10.13 :

  - The WCP dissector could crash. wnpa-sec-2015-07
    CVE-2015-2188 [bnc#920696]

  - The pcapng file parser could crash. wnpa-sec-2015-08
    CVE-2015-2189 [bnc#920697]

  - The TNEF dissector could go into an infinite loop.
    wnpa-sec-2015-10 CVE-2015-2191 [bnc#920699]

  - Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.10.1
    3.html

The following security issues were fixed in 1.12.4 :

  - The following security issues were fixed :

  - The ATN-CPDLC dissector could crash. wnpa-sec-2015-06
    CVE-2015-2187 [bnc#920695]

  - The WCP dissector could crash. wnpa-sec-2015-07
    CVE-2015-2188 [bnc#920696]

  - The pcapng file parser could crash. wnpa-sec-2015-08
    CVE-2015-2189 [bnc#920697]

  - The LLDP dissector could crash. wnpa-sec-2015-09
    CVE-2015-2190 [bnc#920698]

  - The TNEF dissector could go into an infinite loop.
    wnpa-sec-2015-10 CVE-2015-2191 [bnc#920699]

  - The SCSI OSD dissector could go into an infinite loop.
    wnpa-sec-2015-11 CVE-2015-2192 [bnc#920700]

  - Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.12.4
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.4.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"wireshark-1.10.13-36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debuginfo-1.10.13-36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debugsource-1.10.13-36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-devel-1.10.13-36.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-1.12.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debuginfo-1.12.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debugsource-1.12.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-devel-1.12.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-1.12.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-debuginfo-1.12.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-1.12.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-debuginfo-1.12.4-12.1") ) flag++;

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
