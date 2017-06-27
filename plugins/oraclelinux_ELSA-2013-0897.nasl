#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0897 and 
# Oracle Linux Security Advisory ELSA-2013-0897 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68832);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:16:04 $");

  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_bugtraq_id(60149, 60285);
  script_osvdb_id(93678, 93856);
  script_xref(name:"RHSA", value:"2013:0897");

  script_name(english:"Oracle Linux 6 : mesa (ELSA-2013-0897)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0897 :

Updated mesa packages that fix multiple security issues are now
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
    value:"https://oss.oracle.com/pipermail/el-errata/2013-June/003505.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mesa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-dri-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGLU-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"glx-utils-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-demos-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-dri-drivers-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-dri-filesystem-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-libGL-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-libGL-devel-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-libGLU-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-libGLU-devel-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-libOSMesa-9.0-0.8.el6_4.3")) flag++;
if (rpm_check(release:"EL6", reference:"mesa-libOSMesa-devel-9.0-0.8.el6_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glx-utils / mesa-demos / mesa-dri-drivers / mesa-dri-filesystem / etc");
}
