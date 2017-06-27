#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:480 and 
# CentOS Errata and Security Advisory 2005:480 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21831);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1739");
  script_bugtraq_id(13705);
  script_osvdb_id(16774, 16775);
  script_xref(name:"RHSA", value:"2005:480");

  script_name(english:"CentOS 3 / 4 : ImageMagick (CESA-2005:480)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix a denial of service issue are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick(TM) is an image display and manipulation tool for the X
Window System that can read and write multiple image formats.

A denial of service bug was found in the way ImageMagick parses XWD
files. A user or program executing ImageMagick to process a malicious
XWD file can cause ImageMagick to enter an infinite loop causing a
denial of service condition. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-1739 to this
issue.

Users of ImageMagick should upgrade to these updated packages, which
contain a backported patch, and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011780.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd8db7d7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7852d4ef"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011789.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e99bec5c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011790.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0404c95b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011792.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdd54d94"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011793.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3d490eb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/21");
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
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-5.5.6-15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-5.5.6-15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-devel-5.5.6-15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-devel-5.5.6-15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-perl-5.5.6-15")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ImageMagick-6.0.7.1-12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-c++-6.0.7.1-12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-c++-devel-6.0.7.1-12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-devel-6.0.7.1-12")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-perl-6.0.7.1-12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
