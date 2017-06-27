#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:102 and 
# CentOS Errata and Security Advisory 2005:102 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21919);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0201");
  script_osvdb_id(13446);
  script_xref(name:"RHSA", value:"2005:102");

  script_name(english:"CentOS 4 : dbus (CESA-2005:102)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dbus packages that fix a security issue are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

D-BUS is a system for sending messages between applications. It is
used both for the systemwide message bus service, and as a
per-user-login-session messaging facility.

Dan Reed discovered that a user can send and listen to messages on
another user's per-user session bus if they know the address of the
socket. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0201 to this issue. In
Red Hat Enterprise Linux 4, the per-user session bus is only used for
printing notifications, therefore this issue would only allow a local
user to examine or send additional print notification messages.

Users of dbus are advised to upgrade to these updated packages, which
contain backported patches to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011798.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b4c03ed"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011804.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e3685e0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011805.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23622a97"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dbus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/31");
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
if (rpm_check(release:"CentOS-4", reference:"dbus-0.22-12.EL.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-devel-0.22-12.EL.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-glib-0.22-12.EL.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-python-0.22-12.EL.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-x11-0.22-12.EL.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
