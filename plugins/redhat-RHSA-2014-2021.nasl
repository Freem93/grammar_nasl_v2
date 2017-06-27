#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:2021. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80115);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/19 17:45:48 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-9029");
  script_xref(name:"RHSA", value:"2014:2021");

  script_name(english:"RHEL 6 / 7 : jasper (RHSA-2014:2021)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jasper packages that fix three security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

JasPer is an implementation of Part 1 of the JPEG 2000 image
compression standard.

Multiple off-by-one flaws, leading to heap-based buffer overflows,
were found in the way JasPer decoded JPEG 2000 image files. A
specially crafted file could cause an application using JasPer to
crash or, possibly, execute arbitrary code. (CVE-2014-9029)

A heap-based buffer overflow flaw was found in the way JasPer decoded
JPEG 2000 image files. A specially crafted file could cause an
application using JasPer to crash or, possibly, execute arbitrary
code. (CVE-2014-8138)

A double free flaw was found in the way JasPer parsed ICC color
profiles in JPEG 2000 image files. A specially crafted file could
cause an application using JasPer to crash or, possibly, execute
arbitrary code. (CVE-2014-8137)

Red Hat would like to thank oCERT for reporting these issues. oCERT
acknowledges Jose Duart of the Google Security Team as the original
reporter.

All JasPer users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All
applications using the JasPer libraries must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-2021.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jasper-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

exit(0, "Disabled temporarily.");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jasper-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jasper-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jasper-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", reference:"jasper-debuginfo-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", reference:"jasper-devel-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"jasper-devel-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", reference:"jasper-libs-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"jasper-utils-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"jasper-utils-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jasper-utils-1.900.1-16.el6_6.2")) flag++;


if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"jasper-1.900.1-26.el7_0.2")) flag++;

if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jasper-1.900.1-26.el7_0.2")) flag++;

if (rpm_check(release:"RHEL7", reference:"jasper-debuginfo-1.900.1-26.el7_0.2")) flag++;

if (rpm_check(release:"RHEL7", reference:"jasper-devel-1.900.1-26.el7_0.2")) flag++;

if (rpm_check(release:"RHEL7", reference:"jasper-libs-1.900.1-26.el7_0.2")) flag++;

if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"jasper-utils-1.900.1-26.el7_0.2")) flag++;

if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jasper-utils-1.900.1-26.el7_0.2")) flag++;



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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-devel / jasper-libs / etc");
}
