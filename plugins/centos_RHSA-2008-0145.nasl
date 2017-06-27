#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0145 and 
# CentOS Errata and Security Advisory 2008:0145 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31995);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-1097");
  script_bugtraq_id(23347, 25763, 28821, 28822);
  script_osvdb_id(43213);
  script_xref(name:"RHSA", value:"2008:0145");

  script_name(english:"CentOS 3 / 4 / 5 : ImageMagick (CESA-2008:0145)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that correct several security issues are
now available for Red Hat Enterprise Linux versions 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

Several heap-based buffer overflow flaws were found in ImageMagick. If
a victim opened a specially crafted DCM or XWD file, an attacker could
potentially execute arbitrary code on the victim's machine.
(CVE-2007-1797)

Several denial of service flaws were found in ImageMagick's parsing of
XCF and DCM files. Attempting to process a specially crafted input
file in these formats could cause ImageMagick to enter an infinite
loop. (CVE-2007-4985)

Several integer overflow flaws were found in ImageMagick. If a victim
opened a specially crafted DCM, DIB, XBM, XCF or XWD file, an attacker
could potentially execute arbitrary code with the privileges of the
user running ImageMagick. (CVE-2007-4986)

An integer overflow flaw was found in ImageMagick's DIB parsing code.
If a victim opened a specially crafted DIB file, an attacker could
potentially execute arbitrary code with the privileges of the user
running ImageMagick. (CVE-2007-4988)

A heap-based buffer overflow flaw was found in the way ImageMagick
parsed XCF files. If a specially crafted XCF image was opened,
ImageMagick could be made to overwrite heap memory beyond the bounds
of its allocated memory. This could, potentially, allow an attacker to
execute arbitrary code on the machine running ImageMagick.
(CVE-2008-1096)

A heap-based buffer overflow flaw was found in ImageMagick's
processing of certain malformed PCX images. If a victim opened a
specially crafted PCX file, an attacker could possibly execute
arbitrary code on the victim's machine. (CVE-2008-1097)

All users of ImageMagick should upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014820.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d439be4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ac612dc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ebc27d7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?840730e4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5eb4e379"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bf92a77"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e10eb29"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98396b19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
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
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-5.5.6-28")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-5.5.6-28")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-devel-5.5.6-28")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-devel-5.5.6-28")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-perl-5.5.6-28")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-6.0.7.1-17.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-c++-6.0.7.1-17.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-devel-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-c++-devel-6.0.7.1-17.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-devel-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-devel-6.0.7.1-17.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-devel-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-perl-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-perl-6.0.7.1-17.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-perl-6.0.7.1-17.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ImageMagick-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-c++-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-c++-devel-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-devel-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-perl-6.2.8.0-4.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
