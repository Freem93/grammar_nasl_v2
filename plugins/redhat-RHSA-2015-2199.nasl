#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2199. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86937);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2013-7423", "CVE-2015-1472", "CVE-2015-1473", "CVE-2015-1781");
  script_osvdb_id(117751, 117873, 121105);
  script_xref(name:"RHSA", value:"2015:2199");

  script_name(english:"RHEL 7 : glibc (RHSA-2015:2199)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix multiple security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

It was discovered that, under certain circumstances, glibc's
getaddrinfo() function would send DNS queries to random file
descriptors. An attacker could potentially use this flaw to send DNS
queries to unintended recipients, resulting in information disclosure
or data loss due to the application encountering corrupted data.
(CVE-2013-7423)

A buffer overflow flaw was found in the way glibc's gethostbyname_r()
and other related functions computed the size of a buffer when passed
a misaligned buffer as input. An attacker able to make an application
call any of these functions with a misaligned buffer could use this
flaw to crash the application or, potentially, execute arbitrary code
with the permissions of the user running the application.
(CVE-2015-1781)

A heap-based buffer overflow flaw and a stack overflow flaw were found
in glibc's swscanf() function. An attacker able to make an application
call the swscanf() function could use these flaws to crash that
application or, potentially, execute arbitrary code with the
permissions of the user running the application. (CVE-2015-1472,
CVE-2015-1473)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in glibc's _IO_wstr_overflow() function. An attacker able to
make an application call this function could use this flaw to crash
that application or, potentially, execute arbitrary code with the
permissions of the user running the application. (BZ#1195762)

A flaw was found in the way glibc's fnmatch() function processed
certain malformed patterns. An attacker able to make an application
call this function could use this flaw to crash that application.
(BZ#1197730)

The CVE-2015-1781 issue was discovered by Arjun Shankar of Red Hat.

These updated glibc packages also include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. For information on the most significant of these changes,
users are directed to the following article on the Red Hat Customer
Portal :

https://access.redhat.com/articles/2050743

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-7423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1781.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2050743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2199.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
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
  rhsa = "RHSA-2015:2199";
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
  if (rpm_check(release:"RHEL7", reference:"glibc-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-common-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-common-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-common-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-devel-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-headers-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-headers-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"glibc-static-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-utils-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-utils-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nscd-2.17-105.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nscd-2.17-105.el7")) flag++;

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
