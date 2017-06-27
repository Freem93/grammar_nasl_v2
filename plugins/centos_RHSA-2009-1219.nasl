#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1219 and 
# CentOS Errata and Security Advisory 2009:1219 respectively.
#

include("compat.inc");

if (description)
{
  script_id(40626);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-2663");
  script_bugtraq_id(36018);
  script_xref(name:"RHSA", value:"2009:1219");

  script_name(english:"CentOS 3 / 5 : libvorbis (CESA-2009:1219)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvorbis packages that fix one security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libvorbis packages contain runtime libraries for use in programs
that support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

An insufficient input validation flaw was found in the way libvorbis
processes the codec file headers (static mode headers and encoding
books) of the Ogg Vorbis audio file format (Ogg). A remote attacker
could provide a specially crafted Ogg file that would cause a denial
of service (memory corruption and application crash) or, potentially,
execute arbitrary code with the privileges of an application using the
libvorbis library when opened by a victim. (CVE-2009-2663)

Users of libvorbis should upgrade to these updated packages, which
contain a backported patch to correct this issue. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1db006a0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016094.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4c2837f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72c15658"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89032d6e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvorbis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libvorbis-1.0-11.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libvorbis-1.0-11.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libvorbis-devel-1.0-11.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libvorbis-devel-1.0-11.el3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libvorbis-1.1.2-3.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvorbis-devel-1.1.2-3.el5_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
