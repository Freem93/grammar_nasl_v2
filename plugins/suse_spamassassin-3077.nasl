#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update spamassassin-3077.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27451);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:36:49 $");

  script_cve_id("CVE-2007-0451");

  script_name(english:"openSUSE 10 Security Update : spamassassin (spamassassin-3077)");
  script_summary(english:"Check for the spamassassin-3077 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This upgrade brings spamassassin to version 3.1.8 with following
changes :

  - fix for CVE-2007-0451: possible DoS due to incredibly
    long URIs found in the message content.

  - disable perl module usage in update channels unless

    --allowplugins is specified

  - files with names starting/ending in whitespace weren't
    usable

  - remove Text::Wrap related code due to upstream issues

  - update spamassassin and sa-learn to better deal with
    STDIN

  - improvements and bug fixes related to DomainKeys and
    DKIM support

  - several updates for Received header parsing

  - several documentation updates and random taint-variable
    related issues

This update also adds some missing dependencies."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spamassassin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"perl-spamassassin-3.1.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"spamassassin-3.1.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"perl-spamassassin-3.1.8-9.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"spamassassin-3.1.8-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spamassassin");
}
