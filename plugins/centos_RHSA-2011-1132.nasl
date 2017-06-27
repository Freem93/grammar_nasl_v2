#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1132 and 
# CentOS Errata and Security Advisory 2011:1132 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56269);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2011-2200");
  script_bugtraq_id(48216);
  script_osvdb_id(72896);
  script_xref(name:"RHSA", value:"2011:1132");

  script_name(english:"CentOS 5 : dbus (CESA-2011:1132)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dbus packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

D-Bus is a system for sending messages between applications. It is
used for the system-wide message bus service and as a
per-user-login-session messaging facility.

A denial of service flaw was found in the way the D-Bus library
handled endianness conversion when receiving messages. A local user
could use this flaw to send a specially crafted message to dbus-daemon
or to a service using the bus, such as Avahi or NetworkManager,
possibly causing the daemon to exit or the service to disconnect from
the bus. (CVE-2011-2200)

All users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to
take effect, all running instances of dbus-daemon and all running
applications using the libdbus library must be restarted, or the
system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017794.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72f8d940"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017795.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df8ba40b"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000238.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa56a0fc"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cb198d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dbus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"dbus-1.1.2-16.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-devel-1.1.2-16.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-libs-1.1.2-16.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-x11-1.1.2-16.el5_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
