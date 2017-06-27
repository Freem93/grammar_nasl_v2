#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:413 and 
# CentOS Errata and Security Advisory 2005:413 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21821);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1275");
  script_osvdb_id(15891);
  script_xref(name:"RHSA", value:"2005:413");

  script_name(english:"CentOS 3 / 4 : ImageMagick (CESA-2005:413)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix a buffer overflow issue are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

ImageMagick(TM) is an image display and manipulation tool for the X
Window System which can read and write multiple image formats.

A heap based buffer overflow bug was found in the way ImageMagick
parses PNM files. An attacker could execute arbitrary code on a
victim's machine if they were able to trick the victim into opening a
specially crafted PNM file. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-1275 to this
issue.

Users of ImageMagick should upgrade to these updated packages, which
contain a backported patch, and are not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011759.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011763.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011764.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"ImageMagick-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"ImageMagick-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"ImageMagick-c++-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"ImageMagick-c++-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"ImageMagick-c++-devel-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"ImageMagick-c++-devel-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"ImageMagick-devel-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"ImageMagick-devel-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"ImageMagick-perl-5.5.6-14")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"ImageMagick-perl-5.5.6-14")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-devel-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-devel-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-devel-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-perl-6.0.7.1-11")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-perl-6.0.7.1-11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
