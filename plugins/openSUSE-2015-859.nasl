#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-859.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87437);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/17 15:21:31 $");

  script_cve_id("CVE-2015-8077");

  script_name(english:"openSUSE Security Update : cyrus-imapd (openSUSE-2015-859)");
  script_summary(english:"Check for the openSUSE-2015-859 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cyrus-imapd fixes the following issues :

  - Added cyrus-imapd-2.3.19-cve-2015-8077.patch:
    boo#954200, CVE-2015-8077: Integer overflow in range
    checks"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954200"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-imapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");
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

if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-2.3.19-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-debuginfo-2.3.19-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-debugsource-2.3.19-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cyrus-imapd-devel-2.3.19-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-IMAP-2.3.19-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-IMAP-debuginfo-2.3.19-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-SIEVE-managesieve-2.3.19-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-Cyrus-SIEVE-managesieve-debuginfo-2.3.19-34.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-debuginfo / cyrus-imapd-debugsource / etc");
}
