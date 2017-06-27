#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0897. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66772);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_bugtraq_id(60149);
  script_osvdb_id(93678, 93856);
  script_xref(name:"RHSA", value:"2013:0897");

  script_name(english:"RHEL 6 : mesa (RHSA-2013:0897)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mesa packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mesa provides a 3D graphics API that is compatible with Open Graphics
Library (OpenGL). It also provides hardware-accelerated drivers for
many popular graphics chips.

An out-of-bounds access flaw was found in Mesa. If an application
using Mesa exposed the Mesa API to untrusted inputs (Mozilla Firefox
does this), an attacker could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2013-1872)

It was found that Mesa did not correctly validate messages from the X
server. A malicious X server could cause an application using Mesa to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2013-1993)

All users of Mesa are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications linked against Mesa must be restarted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1993.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0897.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-dri-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGLU-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");
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
  rhsa = "RHSA-2013:0897";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glx-utils-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glx-utils-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glx-utils-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-debuginfo-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mesa-demos-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mesa-demos-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mesa-demos-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-dri-drivers-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-dri-filesystem-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-libGL-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-libGL-devel-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-libGLU-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-libGLU-devel-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-libOSMesa-9.0-0.8.el6_4.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mesa-libOSMesa-devel-9.0-0.8.el6_4.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glx-utils / mesa-debuginfo / mesa-demos / mesa-dri-drivers / etc");
  }
}
