#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0008 and 
# CentOS Errata and Security Advisory 2007:0008 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24285);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/28 23:45:04 $");

  script_cve_id("CVE-2006-6107");
  script_osvdb_id(32279);
  script_xref(name:"RHSA", value:"2007:0008");

  script_name(english:"CentOS 4 : dbus (CESA-2007:0008)");
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

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

D-BUS is a system for sending messages between applications. It is
used both for the systemwide message bus service, and as a
per-user-login-session messaging facility.

Kimmo Hamalainen discovered a flaw in the way D-BUS processes certain
messages. It is possible for a local unprivileged D-BUS process to
disrupt the ability of another D-BUS process to receive messages.
(CVE-2006-6107)

Users of dbus are advised to upgrade to these updated packages, which
contain backported patches to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbd51535"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d37ee756"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce3f5546"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dbus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"dbus-0.22-12.EL.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-devel-0.22-12.EL.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-glib-0.22-12.EL.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-python-0.22-12.EL.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"dbus-x11-0.22-12.EL.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
