#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0005 and 
# CentOS Errata and Security Advisory 2009:0005 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35311);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:43:05 $");

  script_cve_id("CVE-2005-0706");
  script_xref(name:"RHSA", value:"2009:0005");

  script_name(english:"CentOS 3 / 4 : gnome-vfs2 (CESA-2009:0005)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated GNOME VFS packages that fix a security issue are now available
for Red Hat Enterprise Linux 2.1, 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNOME VFS is the GNOME virtual file system. It provides a modular
architecture and ships with several modules that implement support for
various local and remote file systems as well as numerous protocols,
including HTTP, FTP, and others.

A buffer overflow flaw was discovered in the GNOME virtual file system
when handling data returned by CDDB servers. If a user connected to a
malicious CDDB server, an attacker could use this flaw to execute
arbitrary code on the victim's machine. (CVE-2005-0706)

Users of gnome-vfs and gnome-vfs2 are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue. All running GNOME sessions must be restarted for the update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015583.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?267817a0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015585.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5c8838c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f428961d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5985e6eb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015550.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67f8fd2d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52243b72"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-vfs2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-vfs2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-vfs2-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/08");
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
if (rpm_check(release:"CentOS-3", reference:"gnome-vfs2-2.2.5-2E.3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gnome-vfs2-devel-2.2.5-2E.3.3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnome-vfs2-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gnome-vfs2-2.8.2-8.7.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnome-vfs2-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnome-vfs2-devel-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gnome-vfs2-devel-2.8.2-8.7.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnome-vfs2-devel-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnome-vfs2-smb-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gnome-vfs2-smb-2.8.2-8.7.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnome-vfs2-smb-2.8.2-8.7.el4_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
