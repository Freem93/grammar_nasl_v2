#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-417.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99155);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-8743");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2017-417)");
  script_summary(english:"Check for the openSUSE-2017-417 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apache2 provides the following fixes :

Security issues fixed :

  - CVE-2016-0736: Protect mod_session_crypto data with a
    MAC to prevent padding oracle attacks (bsc#1016712).

  - CVE-2016-2161: Malicious input to mod_auth_digest could
    have caused the server to crash, resulting in DoS
    (bsc#1016714).

  - CVE-2016-8743: Added new directive 'HttpProtocolOptions
    Strict' to avoid proxy chain misinterpretation
    (bsc#1016715).

Bugfixes :

  - Add NotifyAccess=all to systemd service files to prevent
    warnings in the log when using mod_systemd (bsc#980663).

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980663"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"apache2-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-debuginfo-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-debugsource-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-devel-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-event-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-event-debuginfo-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-example-pages-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-prefork-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-prefork-debuginfo-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-utils-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-utils-debuginfo-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-worker-2.4.16-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-worker-debuginfo-2.4.16-18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
