#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0451. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58586);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");
  script_bugtraq_id(52865);
  script_osvdb_id(81009, 81010, 81011);
  script_xref(name:"RHSA", value:"2012:0451");

  script_name(english:"RHEL 5 / 6 : rpm (RHSA-2012:0451)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpm packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6; Red Hat Enterprise
Linux 3 and 4 Extended Life Cycle Support; Red Hat Enterprise Linux
5.3 Long Life; and Red Hat Enterprise Linux 5.6, 6.0 and 6.1 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The RPM Package Manager (RPM) is a command-line driven package
management system capable of installing, uninstalling, verifying,
querying, and updating software packages.

Multiple flaws were found in the way RPM parsed package file headers.
An attacker could create a specially crafted RPM package that, when
its package header was accessed, or during package signature
verification, could cause an application using the RPM library (such
as the rpm command line tool, or the yum and up2date package managers)
to crash or, potentially, execute arbitrary code. (CVE-2012-0060,
CVE-2012-0061, CVE-2012-0815)

Note: Although an RPM package can, by design, execute arbitrary code
when installed, this issue would allow a specially crafted RPM package
to execute arbitrary code before its digital signature has been
verified. Package downloads from the Red Hat Network are protected by
the use of a secure HTTPS connection in addition to the RPM package
signature checks.

All RPM users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running applications
linked against the RPM library must be restarted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0451.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0451";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"popt-1.10.2.3-22.el5_6.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"popt-1.10.2.3-28.el5_8")) flag++; }

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"popt-1.10.2.3-9.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"popt-1.10.2.3-9.el5_3.3")) flag++;

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"rpm-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rpm-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"rpm-4.4.2.3-22.el5_6.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rpm-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"rpm-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rpm-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-apidocs-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"rpm-apidocs-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rpm-apidocs-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"rpm-apidocs-4.4.2.3-22.el5_6.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rpm-apidocs-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-apidocs-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"rpm-apidocs-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rpm-apidocs-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-build-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"rpm-build-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rpm-build-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"rpm-build-4.4.2.3-22.el5_6.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rpm-build-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-build-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"rpm-build-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rpm-build-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"rpm-devel-4.4.2.3-22.el5_6.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"rpm-devel-4.4.2.3-28.el5_8")) flag++; }

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"rpm-devel-4.4.2.3-9.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"rpm-devel-4.4.2.3-9.el5_3.3")) flag++;

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"rpm-libs-4.4.2.3-22.el5_6.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"rpm-libs-4.4.2.3-28.el5_8")) flag++; }

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"rpm-libs-4.4.2.3-9.el5_3.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"rpm-libs-4.4.2.3-9.el5_3.3")) flag++;

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-python-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"rpm-python-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rpm-python-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"rpm-python-4.4.2.3-22.el5_6.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rpm-python-4.4.2.3-28.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-python-4.4.2.3-22.el5_6.3")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"rpm-python-4.4.2.3-9.el5_3.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rpm-python-4.4.2.3-28.el5_8")) flag++; }


if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"rpm-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"rpm-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rpm-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"rpm-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"rpm-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rpm-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"rpm-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"rpm-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rpm-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", reference:"rpm-apidocs-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", reference:"rpm-apidocs-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", reference:"rpm-apidocs-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"rpm-build-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"rpm-build-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rpm-build-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"rpm-build-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"rpm-build-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rpm-build-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"rpm-build-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"rpm-build-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rpm-build-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", reference:"rpm-cron-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", reference:"rpm-cron-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", reference:"rpm-cron-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", reference:"rpm-debuginfo-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", reference:"rpm-debuginfo-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", reference:"rpm-debuginfo-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", reference:"rpm-devel-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", reference:"rpm-devel-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", reference:"rpm-devel-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", reference:"rpm-libs-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", reference:"rpm-libs-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", reference:"rpm-libs-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"rpm-python-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"rpm-python-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"rpm-python-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"rpm-python-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"rpm-python-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"rpm-python-4.8.0-19.el6_2.1")) flag++; }

if (sp == "1") {   if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"rpm-python-4.8.0-16.el6_1.2")) flag++; }
else if (sp == "0") {   if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"rpm-python-4.8.0-12.el6_0.2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rpm-python-4.8.0-19.el6_2.1")) flag++; }


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "popt / rpm / rpm-apidocs / rpm-build / rpm-cron / rpm-debuginfo / etc");
  }
}
