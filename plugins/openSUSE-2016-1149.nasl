#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1149.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93852);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/17 13:39:45 $");

  script_cve_id("CVE-2016-6323");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-2016-1149)");
  script_summary(english:"Check for the openSUSE-2016-1149 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following issues :

Security issues fixed :

  - arm: mark __startcontext as .cantunwind (CVE-2016-6323,
    boo#994359, BZ #20435)

Bugs fixed :

  - aarch64: Merge __local_multiple_threads offset with
    memory reference

  - Fix memory leak in regexp compiler (BZ #17069)

  - Provide correct buffer length to netgroup queries in
    nscd (BZ #16695)

  - Use NSS_STATUS_TRYAGAIN to indicate insufficient buffer
    (BZ #16878)

  - aarch64: End frame record chain correctly (BZ #17555)

  - _IO_wstr_overflow integer overflow (BZ #17269)

  - Fix nscd lookup when netgroup has wildcards (BZ #16758,
    BZ #16759)

  - Avoid overlapping addresses to stpcpy calls in nscd (BZ
    #16760)

  - resolv: Always set *resplen2 out parameter in send_dg
    (boo#994576, BZ #19791)

  - Fix memory handling in strxfrm_l (BZ #16009)

  - Harden tls_dtor_list with pointer mangling (BZ #19018)

  - open and openat ignore 'mode' with O_TMPFILE in flags
    (BZ #17523)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994576"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"glibc-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-debuginfo-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-debugsource-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-debuginfo-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-devel-static-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-extra-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-extra-debuginfo-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-html-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-i18ndata-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-info-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-locale-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-locale-debuginfo-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-obsolete-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-obsolete-debuginfo-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-profile-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-debuginfo-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"glibc-utils-debugsource-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nscd-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nscd-debuginfo-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-devel-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-locale-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-profile-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-utils-32bit-2.19-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.19-16.28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc-utils / glibc-utils-32bit / glibc-utils-debuginfo / etc");
}
