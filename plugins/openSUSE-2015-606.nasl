#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-606.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86139);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/25 13:40:02 $");

  script_name(english:"openSUSE Security Update : cyrus-imapd (openSUSE-2015-606)");
  script_summary(english:"Check for the openSUSE-2015-606 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides version 2.4.18 of cyrus-imapd

  - Security fix: handle urlfetch range starting outside
    message range

  - A bunch of cleanups and fixes to compiling

  - A bunch of sieve cleanups

  - Enhanced SSL/TLS configuration options

  - Disable use of SSLv2/SSLv3

  - Allow SQL backend for mboxlist and statuscache (thanks
    Julien Coloos)

  - Fixed T116: correct LIST response for domains starting
    with 'inbox.'

  - Fixed T76: fixed lmtpd userdeny db checks (thanks Leena
    Heino)

  - Fixed bug #3856: lmtpd now performs userdeny checks

  - Fixed bug #3848: support charset aliases in encoded
    headers

  - Fixed bug #3853: disconnect_on_vanished_mailbox: release
    mailbox lock before exiting (thanks Wolfgang Breyha)

  - Fixed bug #3415: fixed nntpd LIST/GROUP bug

  - Fixed bug #3784: no longer crash in THREAD REFERENCES
    when messages reference themselves

  - Fixed bug #3757: don't segfault on mailbox close with no
    user"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945844"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyradm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-IMAP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-IMAP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-SIEVE-managesieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Cyrus-SIEVE-managesieve-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"cyradm-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cyrus-imapd-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cyrus-imapd-debuginfo-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cyrus-imapd-debugsource-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cyrus-imapd-devel-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cyrus-imapd-snmp-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cyrus-imapd-snmp-mibs-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cyrus-imapd-utils-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-Cyrus-IMAP-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-Cyrus-IMAP-debuginfo-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-Cyrus-SIEVE-managesieve-2.4.18-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-Cyrus-SIEVE-managesieve-debuginfo-2.4.18-2.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyradm / cyrus-imapd / cyrus-imapd-debuginfo / etc");
}
