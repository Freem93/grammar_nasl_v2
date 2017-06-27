#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1561 and 
# CentOS Errata and Security Advisory 2009:1561 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67071);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-3379");
  script_bugtraq_id(36875);
  script_xref(name:"RHSA", value:"2009:1561");

  script_name(english:"CentOS 3 / 4 / 5 : libvorbis (CESA-2009:1561)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvorbis packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libvorbis packages contain runtime libraries for use in programs
that support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

Multiple flaws were found in the libvorbis library. A specially
crafted Ogg Vorbis media format file (Ogg) could cause an application
using libvorbis to crash or, possibly, execute arbitrary code when
opened. (CVE-2009-3379)

Users of libvorbis should upgrade to these updated packages, which
contain backported patches to correct these issues. The desktop must
be restarted (log out, then log back in) for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016308.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0b5284d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?720e160a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2eb8aa3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016311.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2d94939"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016322.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?175f2720"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016323.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d58768c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvorbis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libvorbis-1.0-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libvorbis-1.0-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libvorbis-devel-1.0-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libvorbis-devel-1.0-12.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-1.1.0-3.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-1.1.0-3.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-devel-1.1.0-3.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-devel-1.1.0-3.el4_8.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libvorbis-1.1.2-3.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvorbis-devel-1.1.2-3.el5_4.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
