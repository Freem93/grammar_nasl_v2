#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-233.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88855);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2014-9761", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8778", "CVE-2015-8779");
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-2016-233)");
  script_summary(english:"Check for the openSUSE-2016-233 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following issues :

  - errorcheck-mutex-no-elision.patch: Don't do lock elision
    on an error checking mutex (boo#956716, BZ #17514)

  - reinitialize-dl_load_write_lock.patch: Reinitialize
    dl_load_write_lock on fork (boo#958315, BZ #19282)

  - send-dg-buffer-overflow.patch: Fix getaddrinfo
    stack-based buffer overflow (CVE-2015-7547, boo#961721,
    BZ #18665)

  - strftime-range-check.patch: Add range check on time
    fields (CVE-2015-8776, boo#962736, BZ #18985)

  - hcreate-overflow-check.patch: Handle overflow in hcreate
    (CVE-2015-8778, boo#962737, BZ #18240)

  - refactor-nan-parsing.patch: Refactor strtod parsing of
    NaN payloads (CVE-2014-9761, boo#962738, BZ #16962)

  - catopen-unbound-alloca.patch: Fix unbound alloca in
    catopen (CVE-2015-8779, boo#962739, BZ #17905)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/19");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"glibc-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-debuginfo-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-debugsource-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-debuginfo-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-static-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-extra-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-extra-debuginfo-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-html-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-i18ndata-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-info-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-locale-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-locale-debuginfo-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-obsolete-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-obsolete-debuginfo-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-profile-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-debuginfo-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-debugsource-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nscd-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nscd-debuginfo-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-devel-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-locale-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-profile-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-utils-32bit-2.19-16.22.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.19-16.22.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc-utils / glibc-utils-32bit / glibc-utils-debuginfo / etc");
}
