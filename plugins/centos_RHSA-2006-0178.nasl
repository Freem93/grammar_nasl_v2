#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0178 and 
# CentOS Errata and Security Advisory 2006:0178 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21888);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/09 14:23:23 $");

  script_cve_id("CVE-2005-4601", "CVE-2006-0082");
  script_bugtraq_id(12717, 16093);
  script_osvdb_id(22121, 22671);
  script_xref(name:"RHSA", value:"2006:0178");

  script_name(english:"CentOS 3 / 4 : ImageMagick (CESA-2006:0178)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix two security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick(TM) is an image display and manipulation tool for the X
Window System that can read and write multiple image formats.

A shell command injection flaw was found in ImageMagick's 'display'
command. It is possible to execute arbitrary commands by tricking a
user into running 'display' on a file with a specially crafted name.
The Common Vulnerabilities and Exposures project (cve.mitre.org)
assigned the name CVE-2005-4601 to this issue.

A format string flaw was discovered in the way ImageMagick handles
filenames. It may be possible to execute arbitrary commands by
tricking a user into running a carefully crafted ImageMagick command.
(CVE-2006-0082)

Users of ImageMagick should upgrade to these updated packages, which
contain backported patches and are not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012659.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?759a2b21"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012660.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d874780f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012662.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?760f1abb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1c5ee01"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012667.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8e877ab"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bad0326c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-5.5.6-18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-5.5.6-18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-devel-5.5.6-18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-devel-5.5.6-18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-perl-5.5.6-18")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-6.0.7.1-14.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-c++-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-6.0.7.1-14.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-devel-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-c++-devel-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.0.7.1-14.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-devel-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-devel-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-devel-6.0.7.1-14.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-perl-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ImageMagick-perl-6.0.7.1-14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-perl-6.0.7.1-14.c4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
