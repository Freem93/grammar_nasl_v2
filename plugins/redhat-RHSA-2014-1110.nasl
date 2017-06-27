#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1110. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77464);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-0475", "CVE-2014-5119");
  script_osvdb_id(108943, 109188);
  script_xref(name:"RHSA", value:"2014:1110");

  script_name(english:"RHEL 5 / 6 / 7 : glibc (RHSA-2014:1110)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues are now available
for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

An off-by-one heap-based buffer overflow flaw was found in glibc's
internal __gconv_translit_find() function. An attacker able to make an
application call the iconv_open() function with a specially crafted
argument could possibly use this flaw to execute arbitrary code with
the privileges of that application. (CVE-2014-5119)

A directory traversal flaw was found in the way glibc loaded locale
files. An attacker able to make an application use a specially crafted
locale name value (for example, specified in an LC_* environment
variable) could possibly use this flaw to execute arbitrary code with
the privileges of that application. (CVE-2014-0475)

Red Hat would like to thank Stephane Chazelas for reporting
CVE-2014-0475.

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5119.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/solutions/1176253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1110.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1110";
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
  if (rpm_check(release:"RHEL5", reference:"glibc-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-common-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-common-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-common-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"glibc-debuginfo-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-debuginfo-common-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"glibc-devel-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-headers-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-headers-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-headers-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-utils-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-utils-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-utils-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nscd-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nscd-2.5-118.el5_10.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nscd-2.5-118.el5_10.3")) flag++;


  if (rpm_check(release:"RHEL6", reference:"glibc-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-common-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-common-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-common-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-common-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-devel-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-headers-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-headers-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-headers-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-static-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-utils-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-utils-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-utils-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nscd-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nscd-2.12-1.132.el6_5.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nscd-2.12-1.132.el6_5.4")) flag++;


  if (rpm_check(release:"RHEL7", reference:"glibc-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-common-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-common-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-common-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-devel-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-headers-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-headers-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-static-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-utils-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-utils-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nscd-2.17-55.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nscd-2.17-55.el7_0.1")) flag++;


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
