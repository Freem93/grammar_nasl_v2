#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0992 and 
# CentOS Errata and Security Advisory 2007:0992 respectively.
#

include("compat.inc");

if (description)
{
  script_id(27543);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2007-5269");
  script_bugtraq_id(25956);
  script_osvdb_id(38273, 38274);
  script_xref(name:"RHSA", value:"2007:0992");

  script_name(english:"CentOS 3 / 4 / 5 : libpng (CESA-2007:0992)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng packages that fix security issues are now available for
Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

Several flaws were discovered in the way libpng handled various PNG
image chunks. An attacker could create a carefully crafted PNG image
file in such a way that it could cause an application linked with
libpng to crash when the file was manipulated. (CVE-2007-5269)

Users should update to these updated packages which contain a
backported patch to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bd42abc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64872fe3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c68bcd3b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?761849f5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de5e8382"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acd979bc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a574ab6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014354.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e375afe1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"libpng-1.2.2-28")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng-devel-1.2.2-28")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng10-1.0.13-18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng10-devel-1.0.13-18")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-1.2.7-3.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpng-1.2.7-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-1.2.7-3.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-devel-1.2.7-3.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpng-devel-1.2.7-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-devel-1.2.7-3.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-1.0.16-3.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpng10-1.0.16-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-1.0.16-3.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-devel-1.0.16-3.el4_5.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libpng10-devel-1.0.16-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-devel-1.0.16-3.el4_5.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libpng-1.2.10-7.1.el5_0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpng-devel-1.2.10-7.1.el5_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
