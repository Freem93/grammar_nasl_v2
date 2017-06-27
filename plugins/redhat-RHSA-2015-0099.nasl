#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0099. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81068);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2015-0235");
  script_osvdb_id(117579);
  script_xref(name:"RHSA", value:"2015:0099");

  script_name(english:"RHEL 5 / 6 : glibc (RHSA-2015:0099) (GHOST)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.6 Long Life, Red Hat Enterprise Linux
5.9 Extended Update Support, Red Hat Enterprise Linux 6.2 Advanced
Update Support, and Red Hat Enterprise Linux 6.4 and 6.5 Extended
Update Support.

Red Hat Product Security has rated this update as having Critical
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

A heap-based buffer overflow was found in glibc's
__nss_hostname_digits_dots() function, which is used by the
gethostbyname() and gethostbyname2() glibc function calls. A remote
attacker able to make an application call either of these functions
could use this flaw to execute arbitrary code with the permissions of
the user running the application. (CVE-2015-0235)

Red Hat would like to thank Qualys for reporting this issue.

All glibc users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0235.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0099.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");
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
if (! ereg(pattern:"^(5\.6|5\.9|6\.2|6\.4|6\.5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.6 / 5.9 / 6.2 / 6.4 / 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0099";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"glibc-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"glibc-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"glibc-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"glibc-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"glibc-common-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"glibc-common-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"glibc-common-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"glibc-common-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"glibc-common-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"glibc-debuginfo-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"glibc-debuginfo-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"glibc-debuginfo-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"glibc-debuginfo-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"glibc-debuginfo-common-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"glibc-debuginfo-common-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"glibc-devel-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"glibc-devel-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"glibc-devel-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"glibc-headers-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"glibc-headers-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"glibc-headers-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"glibc-headers-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"glibc-headers-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"glibc-utils-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"glibc-utils-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"glibc-utils-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"glibc-utils-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"glibc-utils-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"nscd-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"nscd-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"nscd-2.5-107.el5_9.8")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"nscd-2.5-58.el5_6.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"nscd-2.5-107.el5_9.8")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", reference:"glibc-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"glibc-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"glibc-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"glibc-common-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"glibc-common-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"glibc-common-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"glibc-common-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"glibc-common-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-common-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"glibc-common-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"glibc-debuginfo-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"glibc-debuginfo-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"glibc-debuginfo-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-debuginfo-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"glibc-debuginfo-common-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"glibc-debuginfo-common-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"glibc-debuginfo-common-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-debuginfo-common-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"glibc-devel-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"glibc-devel-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"glibc-devel-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-devel-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"glibc-headers-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"glibc-headers-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"glibc-headers-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"glibc-headers-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"glibc-headers-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-headers-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"glibc-headers-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"glibc-static-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"glibc-static-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"glibc-static-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-static-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"glibc-utils-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"glibc-utils-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"glibc-utils-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"glibc-utils-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"glibc-utils-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"glibc-utils-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"glibc-utils-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nscd-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"nscd-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"nscd-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"nscd-2.12-1.132.el6_5.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"nscd-2.12-1.107.el6_4.7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nscd-2.12-1.47.el6_2.15")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"nscd-2.12-1.132.el6_5.5")) flag++;

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
