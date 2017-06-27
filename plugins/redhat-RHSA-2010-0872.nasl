#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0872. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50640);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-3847", "CVE-2010-3856");
  script_bugtraq_id(44154, 44347);
  script_osvdb_id(68721, 68920);
  script_xref(name:"RHSA", value:"2010:0872");

  script_name(english:"RHEL 6 : glibc (RHSA-2010:0872)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues and two bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

It was discovered that the glibc dynamic linker/loader did not handle
the $ORIGIN dynamic string token set in the LD_AUDIT environment
variable securely. A local attacker with write access to a file system
containing setuid or setgid binaries could use this flaw to escalate
their privileges. (CVE-2010-3847)

It was discovered that the glibc dynamic linker/loader did not perform
sufficient safety checks when loading dynamic shared objects (DSOs) to
provide callbacks for its auditing API during the execution of
privileged programs. A local attacker could use this flaw to escalate
their privileges via a carefully-chosen system DSO library containing
unsafe constructors. (CVE-2010-3856)

Red Hat would like to thank Tavis Ormandy for reporting the
CVE-2010-3847 issue, and Ben Hawkes and Tavis Ormandy for reporting
the CVE-2010-3856 issue.

This update also fixes the following bugs :

* Previously, the generic implementation of the strstr() and memmem()
functions did not handle certain periodic patterns correctly and could
find a false positive match. This error has been fixed, and both
functions now work as expected. (BZ#643341)

* The 'TCB_ALIGNMENT' value has been increased to 32 bytes to prevent
applications from crashing during symbol resolution on 64-bit systems
with support for Intel AVX vector registers. (BZ#643343)

All users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3856.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0872.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2010:0872";
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
  if (rpm_check(release:"RHEL6", reference:"glibc-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-common-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-common-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-common-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-devel-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-headers-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-headers-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-headers-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-static-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-static-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-static-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-utils-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-utils-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-utils-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nscd-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nscd-2.12-1.7.el6_0.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nscd-2.12-1.7.el6_0.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-devel / etc");
  }
}
