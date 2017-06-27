#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0146 and 
# CentOS Errata and Security Advisory 2008:0146 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31310);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2006-4484", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3475", "CVE-2007-3476");
  script_bugtraq_id(19582, 24089, 24651);
  script_xref(name:"RHSA", value:"2008:0146");

  script_name(english:"CentOS 4 / 5 : gd (CESA-2008:0146)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gd packages that fix multiple security issues are now
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
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?595ebe08"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed4a13ce"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?620f3d86"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?374ede5c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014739.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1db3fd04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gd-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gd-2.0.28-5.4E.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gd-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gd-devel-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gd-devel-2.0.28-5.4E.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gd-devel-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gd-progs-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gd-progs-2.0.28-5.4E.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gd-progs-2.0.28-5.4E.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"gd-2.0.33-9.4.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gd-devel-2.0.33-9.4.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gd-progs-2.0.33-9.4.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
