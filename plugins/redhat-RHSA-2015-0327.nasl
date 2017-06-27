#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0327. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81630);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-6040", "CVE-2014-8121");
  script_bugtraq_id(73038);
  script_osvdb_id(110668, 110669, 110670, 110671, 110672, 110673, 110675, 119253);
  script_xref(name:"RHSA", value:"2015:0327");

  script_name(english:"RHEL 7 : glibc (RHSA-2015:0327)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

An out-of-bounds read flaw was found in the way glibc's iconv()
function converted certain encoded data to UTF-8. An attacker able to
make an application call the iconv() function with a specially crafted
argument could use this flaw to crash that application.
(CVE-2014-6040)

It was found that the files back end of Name Service Switch (NSS) did
not isolate iteration over an entire database from key-based look-up
API calls. An application performing look-ups on a database while
iterating over it could enter an infinite loop, leading to a denial of
service. (CVE-2014-8121)

This update also fixes the following bugs :

* Due to problems with buffer extension and reallocation, the nscd
daemon terminated unexpectedly with a segmentation fault when
processing long netgroup entries. With this update, the handling of
long netgroup entries has been corrected and nscd no longer crashes in
the described scenario. (BZ#1138520)

* If a file opened in append mode was truncated with the ftruncate()
function, a subsequent ftell() call could incorrectly modify the file
offset. This update ensures that ftell() modifies the stream state
only when it is in append mode and the buffer for the stream is not
empty. (BZ#1156331)

* A defect in the C library headers caused builds with older compilers
to generate incorrect code for the btowc() function in the older
compatibility C++ standard library. Applications calling btowc() in
the compatibility C++ standard library became unresponsive. With this
update, the C library headers have been corrected, and the
compatibility C++ standard library shipped with Red Hat Enterprise
Linux has been rebuilt. Applications that rely on the compatibility
C++ standard library no longer hang when calling btowc(). (BZ#1120490)

* Previously, when using netgroups and the nscd daemon was set up to
cache netgroup information, the sudo utility denied access to valid
users. The bug in nscd has been fixed, and sudo now works in netgroups
as expected. (BZ#1080766)

Users of glibc are advised to upgrade to these updated packages, which
fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8121.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0327.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:0327";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL7", reference:"glibc-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-common-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-common-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-common-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-devel-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-headers-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-headers-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-static-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-utils-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-utils-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nscd-2.17-78.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nscd-2.17-78.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
