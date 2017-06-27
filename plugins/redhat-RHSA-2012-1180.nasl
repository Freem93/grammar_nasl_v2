#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1180. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61603);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:23 $");

  script_cve_id("CVE-2011-2896", "CVE-2012-3403", "CVE-2012-3481");
  script_osvdb_id(74539, 84830, 84831);
  script_xref(name:"RHSA", value:"2012:1180");

  script_name(english:"RHEL 6 : gimp (RHSA-2012:1180)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gimp packages that fix three security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the GIMP's GIF image format plug-in. An attacker could create
a specially crafted GIF image file that, when opened, could cause the
GIF plug-in to crash or, potentially, execute arbitrary code with the
privileges of the user running the GIMP. (CVE-2012-3481)

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the GIMP's GIF
image format plug-in. An attacker could create a specially crafted GIF
image file that, when opened, could cause the GIF plug-in to crash or,
potentially, execute arbitrary code with the privileges of the user
running the GIMP. (CVE-2011-2896)

A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL
file format plug-in. An attacker could create a specially crafted KiSS
palette file that, when opened, could cause the CEL plug-in to crash
or, potentially, execute arbitrary code with the privileges of the
user running the GIMP. (CVE-2012-3403)

Red Hat would like to thank Matthias Weckbecker of the SUSE Security
Team for reporting the CVE-2012-3481 issue.

Users of the GIMP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The GIMP
must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3403.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1180.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-devel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/21");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1180";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gimp-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"gimp-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gimp-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gimp-debuginfo-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gimp-devel-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gimp-devel-tools-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"gimp-devel-tools-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gimp-devel-tools-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gimp-help-browser-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"gimp-help-browser-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gimp-help-browser-2.6.9-4.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gimp-libs-2.6.9-4.el6_3.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-debuginfo / gimp-devel / gimp-devel-tools / etc");
  }
}
