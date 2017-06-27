#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0136 and 
# CentOS Errata and Security Advisory 2012:0136 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57962);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2012-0444");
  script_bugtraq_id(51753);
  script_osvdb_id(78739);
  script_xref(name:"RHSA", value:"2012:0136");

  script_name(english:"CentOS 4 / 5 / 6 : libvorbis (CESA-2012:0136)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvorbis packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The libvorbis packages contain runtime libraries for use in programs
that support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

A heap-based buffer overflow flaw was found in the way the libvorbis
library parsed Ogg Vorbis media files. If a specially crafted Ogg
Vorbis media file was opened by an application using libvorbis, it
could cause the application to crash or, possibly, execute arbitrary
code with the privileges of the user running the application.
(CVE-2012-0444)

Users of libvorbis should upgrade to these updated packages, which
contain a backported patch to correct this issue. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27a3955b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018435.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83b7081f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018436.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4573337"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvorbis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-devel-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-devel-1.1.0-4.el4.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libvorbis-1.1.2-3.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvorbis-devel-1.1.2-3.el5_7.6")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libvorbis-1.2.3-4.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvorbis-devel-1.2.3-4.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvorbis-devel-docs-1.2.3-4.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
