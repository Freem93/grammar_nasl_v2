#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1605. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71009);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4332");
  script_bugtraq_id(57638, 58839, 62324);
  script_osvdb_id(89747, 92038, 97246, 97247, 97248);
  script_xref(name:"RHSA", value:"2013:1605");

  script_name(english:"RHEL 6 : glibc (RHSA-2013:1605)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix three security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in glibc's memory allocator functions (pvalloc,
valloc, and memalign). If an application used such a function, it
could cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2013-4332)

A flaw was found in the regular expression matching routines that
process multibyte character input. If an application utilized the
glibc regular expression matching mechanism, an attacker could provide
specially crafted input that, when processed, would cause the
application to crash. (CVE-2013-0242)

It was found that getaddrinfo() did not limit the amount of stack
memory used during name resolution. An attacker able to make an
application resolve an attacker-controlled hostname or IP address
could possibly cause the application to exhaust all stack memory and
crash. (CVE-2013-1914)

Among other changes, this update includes an important fix for the
following bug :

* Due to a defect in the initial release of the getaddrinfo() system
call in Red Hat enterprise Linux 6.0, AF_INET and AF_INET6 queries
resolved from the /etc/hosts file returned queried names as canonical
names. This incorrect behavior is, however, still considered to be the
expected behavior. As a result of a recent change in getaddrinfo(),
AF_INET6 queries started resolving the canonical names correctly.
However, this behavior was unexpected by applications that relied on
queries resolved from the /etc/hosts file, and these applications
could thus fail to operate properly. This update applies a fix
ensuring that AF_INET6 queries resolved from /etc/hosts always return
the queried name as canonical. Note that DNS lookups are resolved
properly and always return the correct canonical names. A proper fix
to AF_INET6 queries resolution from /etc/hosts may be applied in
future releases; for now, due to a lack of standard, Red Hat suggests
the first entry in the /etc/hosts file, that applies for the IP
address being resolved, to be considered the canonical entry.
(BZ#1022022)

These updated glibc packages also include additional bug fixes and
various enhancements. Space precludes documenting all of these changes
in this advisory. Users are directed to the Red Hat Enterprise Linux
6.5 Technical Notes, linked to in the References, for information on
the most significant of these changes.

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4332.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1605.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1605";
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
  if (rpm_check(release:"RHEL6", reference:"glibc-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-common-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-common-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-common-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-common-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-devel-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-headers-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-headers-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-headers-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-static-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-utils-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-utils-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-utils-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nscd-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nscd-2.12-1.132.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nscd-2.12-1.132.el6")) flag++;

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
