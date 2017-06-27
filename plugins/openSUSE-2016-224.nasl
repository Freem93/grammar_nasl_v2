#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-224.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88829);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2014-9761", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779");
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-2016-224)");
  script_summary(english:"Check for the openSUSE-2016-224 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following security issues :

  - CVE-2015-7547: A stack-based buffer overflow in
    getaddrinfo allowed remote attackers to cause a crash or
    execute arbitrary code via crafted and timed DNS
    responses (bsc#961721)

  - CVE-2015-8777: Insufficient checking of LD_POINTER_GUARD
    environment variable allowed local attackers to bypass
    the pointer guarding protection of the dynamic loader on
    set-user-ID and set-group-ID programs (bsc#950944)

  - CVE-2015-8776: Out-of-range time values passed to the
    strftime function may cause it to crash, leading to a
    denial of service, or potentially disclosure information
    (bsc#962736)

  - CVE-2015-8778: Integer overflow in hcreate and hcreate_r
    could have caused an out-of-bound memory access. leading
    to application crashes or, potentially, arbitrary code
    execution (bsc#962737)

  - CVE-2014-9761: A stack overflow (unbounded alloca) could
    have caused applications which process long strings with
    the nan function to crash or, potentially, execute
    arbitrary code. (bsc#962738)

  - CVE-2015-8779: A stack overflow (unbounded alloca) in
    the catopen function could have caused applications
    which pass long strings to the catopen function to crash
    or, potentially execute arbitrary code. (bsc#962739)

The following non-security bugs were fixed :

  - bsc#955647: Resource leak in resolver

  - bsc#956716: Don't do lock elision on an error checking
    mutex

  - bsc#958315: Reinitialize dl_load_write_lock on fork

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955647"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"glibc-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-debuginfo-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-debugsource-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-devel-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-devel-debuginfo-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-devel-static-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-extra-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-extra-debuginfo-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-html-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-i18ndata-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-info-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-locale-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-locale-debuginfo-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-obsolete-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-obsolete-debuginfo-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-profile-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-utils-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-utils-debuginfo-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"glibc-utils-debugsource-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nscd-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nscd-debuginfo-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-devel-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-locale-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-profile-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-utils-32bit-2.19-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.19-19.1") ) flag++;

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
