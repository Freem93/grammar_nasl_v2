#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:586. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16018);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/28 17:55:16 $");

  script_cve_id("CVE-2004-0968");
  script_osvdb_id(11040);
  script_xref(name:"RHSA", value:"2004:586");

  script_name(english:"RHEL 3 : glibc (RHSA-2004:586)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that address several bugs and implement some
enhancements are now available.

The GNU libc packages (known as glibc) contain the standard C
libraries used by applications.

This errata fixes several bugs in the GNU C Library.

Fixes include (in addition to enclosed Bugzilla entries) :

  - fixed 32-bit atomic operations on 64-bit powerpc - fixed
    -m32 -I /usr/include/nptl compilation on AMD64 - NPTL
    <pthread.h> should now be usable in C++ code or
    -pedantic -std=c89 C - rwlocks are now available also in
    the _POSIX_C_SOURCE=200112L namespace - pthread_once is
    no longer throw(), as the callback routine might throw -
    pthread_create now correctly returns EAGAIN when thread
    couldn't be created because of lack of memory - fixed
    NPTL stack freeing in case of pthread_create failure
    with detached thread - fixed pthread_mutex_timedlock on
    i386 and AMD64 - Itanium gp saving fix in linuxthreads -
    fixed s390/s390x unwinding tests done during
    cancellation if stack frames are small - fixed
    fnmatch(3) backslash handling - fixed out of memory
    behaviour of syslog(3) - resolver ID randomization -
    fixed fim (NaN, NaN) - glob(3) fixes for dangling
    symlinks - catchsegv fixed to work with both 32-bit and
    64-bit binaries on x86-64, s390x and ppc - fixed
    reinitialization of _res when using NPTL stack cache -
    updated bug reporting instructions, removed glibcbug
    script - fixed infinite loop in iconv with some options
    - fixed inet_aton return value - CPU friendlier busy
    waiting in linuxthreads on EM64T and IA-64 - avoid
    blocking/masking debug signal in linuxthreads - fixed
    locale program output when neither LC_ALL nor LANG is
    set - fixed using of uninitialized memory in localedef -
    fixed mntent_r escape processing - optimized mtrace
    script - linuxthread_db fixes on ppc64 - cfi
    instructions in x86-64 linuxthreads vfork - some
    _POSIX_C_SOURCE=200112L namespace fixes

All users of glibc should upgrade to these updated packages, which
resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0968.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-586.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nptl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:586";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"glibc-2.3.2-95.30")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-common-2.3.2-95.30")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-devel-2.3.2-95.30")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-headers-2.3.2-95.30")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-profile-2.3.2-95.30")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-utils-2.3.2-95.30")) flag++;
  if (rpm_check(release:"RHEL3", reference:"nptl-devel-2.3.2-95.30")) flag++;
  if (rpm_check(release:"RHEL3", reference:"nscd-2.3.2-95.30")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-profile / etc");
  }
}
