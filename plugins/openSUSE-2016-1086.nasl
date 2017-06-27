#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1086.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93583);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-8853", "CVE-2016-1238", "CVE-2016-2381", "CVE-2016-6185");

  script_name(english:"openSUSE Security Update : perl (openSUSE-2016-1086)");
  script_summary(english:"Check for the openSUSE-2016-1086 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Perl fixes the following issues :

  - CVE-2016-6185: Xsloader looking at a '(eval)' directory.
    (bsc#988311)

  - CVE-2016-1238: Searching current directory for optional
    modules. (bsc#987887)

  - CVE-2015-8853: Regular expression engine hanging on bad
    utf8. (bsc)

  - CVE-2016-2381: Environment dup handling bug.
    (bsc#967082)

  - 'Insecure dependency in require' error in taint mode.
    (bsc#984906)

  - Memory leak in 'use utf8' handling. (bsc#928292)

  - Missing lock prototype to the debugger. (bsc#932894)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=932894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988311"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/19");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"perl-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-base-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-base-debuginfo-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-debuginfo-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-debugsource-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"perl-32bit-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"perl-base-32bit-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"perl-base-debuginfo-32bit-5.18.2-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.18.2-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-32bit / perl / perl-base-32bit / perl-base / etc");
}
