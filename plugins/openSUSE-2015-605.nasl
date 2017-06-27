#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-605.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86138);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/25 13:40:02 $");

  script_name(english:"openSUSE Security Update : cyrus-imapd (openSUSE-2015-605)");
  script_summary(english:"Check for the openSUSE-2015-605 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This recommended update provides version 2.3.19 of cyrus-imapd

  - Security fix: handle urlfetch range starting outside
    message range

  - Disable use of SSLv2/SSLv3

  - Support for Berkeley DB 5.x (thanks Ondrej Sury)

  - Support for newer glibc versions (thanks Thomas Jarosch)

  - Fixed bug #3465: support for perl 5.14 (thanks
    hsk@imb-jena.de)

  - Fixed bug #3640: reject NULL bytes in headers on LMTP
    delivery (thanks Julien Coloos)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945841"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-IMAP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-IMAP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-SIEVE-managesieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-SIEVE-managesieve-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/25");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-2.3.19-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-debuginfo-2.3.19-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-debugsource-2.3.19-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-devel-2.3.19-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-IMAP-2.3.19-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-IMAP-debuginfo-2.3.19-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-SIEVE-managesieve-2.3.19-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-SIEVE-managesieve-debuginfo-2.3.19-34.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-debuginfo / cyrus-imapd-debugsource / etc");
}
