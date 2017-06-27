#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0176. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88785);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-5229", "CVE-2015-7547");
  script_osvdb_id(132236, 134584);
  script_xref(name:"RHSA", value:"2016:0176");
  script_xref(name:"IAVA", value:"2016-A-0053");
  script_xref(name:"TRA", value:"TRA-2017-08");

  script_name(english:"RHEL 7 : glibc (RHSA-2016:0176)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues and two bugs are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
name service cache daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

A stack-based buffer overflow was found in the way the libresolv
library performed dual A/AAAA DNS queries. A remote attacker could
create a specially crafted DNS response which could cause libresolv to
crash or, potentially, execute code with the permissions of the user
running the library. Note: this issue is only exposed when libresolv
is called from the nss_dns NSS service module. (CVE-2015-7547)

It was discovered that the calloc implementation in glibc could return
memory areas which contain non-zero bytes. This could result in
unexpected application behavior such as hangs or crashes.
(CVE-2015-5229)

The CVE-2015-7547 issue was discovered by the Google Security Team and
Red Hat. Red Hat would like to thank Jeff Layton for reporting the
CVE-2015-5229 issue.

This update also fixes the following bugs :

* The existing implementation of the 'free' function causes all memory
pools beyond the first to return freed memory directly to the
operating system as quickly as possible. This can result in
performance degradation when the rate of free calls is very high. The
first memory pool (the main pool) does provide a method to rate limit
the returns via M_TRIM_THRESHOLD, but this method is not available to
subsequent memory pools.

With this update, the M_TRIM_THRESHOLD method is extended to apply to
all memory pools, which improves performance for threads with very
high amounts of free calls and limits the number of 'madvise' system
calls. The change also increases the total transient memory usage by
processes because the trim threshold must be reached before memory can
be freed.

To return to the previous behavior, you can either set
M_TRIM_THRESHOLD using the 'mallopt' function, or set the
MALLOC_TRIM_THRESHOLD environment variable to 0. (BZ#1298930)

* On the little-endian variant of 64-bit IBM Power Systems (ppc64le),
a bug in the dynamic loader could cause applications compiled with
profiling enabled to fail to start with the error 'monstartup: out of
memory'. The bug has been corrected and applications compiled for
profiling now start correctly. (BZ#1298956)

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5229.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2161461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0176";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL7", reference:"glibc-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-common-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-common-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-common-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-devel-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-headers-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-headers-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-static-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-utils-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-utils-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nscd-2.17-106.el7_2.4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nscd-2.17-106.el7_2.4")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
  }
}
