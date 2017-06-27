#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0317 and 
# CentOS Errata and Security Advisory 2012:0317 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58042);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3026");
  script_osvdb_id(79294);
  script_xref(name:"RHSA", value:"2012:0317");

  script_name(english:"CentOS 4 / 5 / 6 : libpng / libpng10 (CESA-2012:0317)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng and libpng10 packages that fix one security issue are
now available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A heap-based buffer overflow flaw was found in libpng. An attacker
could create a specially crafted PNG image that, when opened, could
cause an application using libpng to crash or, possibly, execute
arbitrary code with the privileges of the user running the
application. (CVE-2011-3026)

Users of libpng and libpng10 should upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications using libpng or libpng10 must be restarted for the update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018445.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc19a848"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018446.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43784130"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018447.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aefae63f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018449.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c74df94c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng and / or libpng10 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-1.2.7-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-1.2.7-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-devel-1.2.7-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-devel-1.2.7-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-1.0.16-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-1.0.16-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-devel-1.0.16-10.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-devel-1.0.16-10.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libpng-1.2.10-15.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpng-devel-1.2.10-15.el5_7")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libpng-1.2.46-2.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpng-devel-1.2.46-2.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpng-static-1.2.46-2.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
