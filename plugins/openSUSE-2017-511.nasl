#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-511.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99700);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id("CVE-2016-9042", "CVE-2017-6451", "CVE-2017-6458", "CVE-2017-6460", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_xref(name:"IAVA", value:"2017-A-0084");

  script_name(english:"openSUSE Security Update : ntp (openSUSE-2017-511)");
  script_summary(english:"Check for the openSUSE-2017-511 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This ntp update to version 4.2.8p10 fixes serveral issues.

This updated enables leap smearing. See
/usr/share/doc/packages/ntp/README.leapsmear for details.

Security issues fixed (bsc#1030050) :

  - CVE-2017-6464: Denial of Service via Malformed Config

  - CVE-2017-6462: Buffer Overflow in DPTS Clock

  - CVE-2017-6463: Authenticated DoS via Malicious Config
    Option

  - CVE-2017-6458: Potential Overflows in ctl_put()
    functions

  - CVE-2017-6451: Improper use of snprintf() in
    mx4200_send()

  - CVE-2017-6460: Buffer Overflow in ntpq when fetching
    reslist

  - CVE-2016-9042: 0rigin (zero origin) DoS.

  - ntpq_stripquotes() returns incorrect Value

  - ereallocarray()/eallocarray() underused

  - Copious amounts of Unused Code

  - Off-by-one in Oncore GPS Receiver

  - Makefile does not enforce Security Flags

Bugfixes :

  - Remove spurious log messages (bsc#1014172).

  - clang scan-build findings

  - Support for openssl-1.1.0 without compatibility modes

  - Bugfix 3072 breaks multicastclient

  - forking async worker: interrupted pipe I/O

  - (...) time_pps_create: Exec format error

  - Incorrect Logic for Peer Event Limiting

  - Change the process name of forked DNS worker

  - Trap Configuration Fail

  - Nothing happens if minsane < maxclock < minclock

  - allow -4/-6 on restrict line with mask

  - out-of-bound pointers in ctl_putsys and decode_bitflags

  - Move ntp-kod to /var/lib/ntp, because /var/db is not a
    standard directory and causes problems for transactional
    updates.

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/321003"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ntp-4.2.8p10-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ntp-debuginfo-4.2.8p10-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ntp-debugsource-4.2.8p10-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ntp-4.2.8p10-29.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ntp-debuginfo-4.2.8p10-29.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ntp-debugsource-4.2.8p10-29.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-debugsource");
}
