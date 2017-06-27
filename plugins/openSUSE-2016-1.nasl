#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87718);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-8614");

  script_name(english:"openSUSE Security Update : claws-mail (openSUSE-2016-1)");
  script_summary(english:"Check for the openSUSE-2016-1 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for claws-mail fixes the following security issue :

  - CVE-2015-8614: buffer overrun issues in Japanese
    character set conversion code could allow an adversary
    to remotely crash claws and potentially have further
    unspecified impact (boo#959993)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959993"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected claws-mail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-3.10.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-debuginfo-3.10.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-debugsource-3.10.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-devel-3.10.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"claws-mail-lang-3.10.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-3.11.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-debuginfo-3.11.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-debugsource-3.11.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-devel-3.11.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"claws-mail-lang-3.11.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"claws-mail-3.12.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"claws-mail-debuginfo-3.12.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"claws-mail-debugsource-3.12.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"claws-mail-devel-3.12.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"claws-mail-lang-3.12.0-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "claws-mail / claws-mail-debuginfo / claws-mail-debugsource / etc");
}
