#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0146 and 
# Oracle Linux Security Advisory ELSA-2008-0146 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67657);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2006-4484", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3475", "CVE-2007-3476");
  script_bugtraq_id(19582, 24089, 24651);
  script_xref(name:"RHSA", value:"2008:0146");

  script_name(english:"Oracle Linux 4 / 5 : gd (ELSA-2008-0146)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0146 :

Updated gd packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gd package contains a graphics library used for the dynamic
creation of images such as PNG and JPEG.

Multiple issues were discovered in the gd GIF image-handling code. A
carefully-crafted GIF file could cause a crash or possibly execute
code with the privileges of the application using the gd library.
(CVE-2006-4484, CVE-2007-3475, CVE-2007-3476)

An integer overflow was discovered in the gdImageCreateTrueColor()
function, leading to incorrect memory allocations. A carefully crafted
image could cause a crash or possibly execute code with the privileges
of the application using the gd library. (CVE-2007-3472)

A buffer over-read flaw was discovered. This could cause a crash in an
application using the gd library to render certain strings using a
JIS-encoded font. (CVE-2007-0455)

A flaw was discovered in the gd PNG image handling code. A truncated
PNG image could cause an infinite loop in an application using the gd
library. (CVE-2007-2756)

A flaw was discovered in the gd X BitMap (XBM) image-handling code. A
malformed or truncated XBM image could cause a crash in an application
using the gd library. (CVE-2007-3473)

Users of gd should upgrade to these updated packages, which contain
backported patches which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-February/000530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-February/000531.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gd-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"gd-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"gd-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"gd-devel-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"gd-devel-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"gd-progs-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"gd-progs-2.0.28-5.4E.el4_6.1")) flag++;

if (rpm_check(release:"EL5", reference:"gd-2.0.33-9.4.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"gd-devel-2.0.33-9.4.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"gd-progs-2.0.33-9.4.el5_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gd / gd-devel / gd-progs");
}
