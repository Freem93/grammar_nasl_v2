#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0616 and 
# CentOS Errata and Security Advisory 2010:0616 respectively.
#

include("compat.inc");

if (description)
{
  script_id(48303);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2010-1172");
  script_osvdb_id(67026);
  script_xref(name:"RHSA", value:"2010:0616");

  script_name(english:"CentOS 5 : NetworkManager / dbus-glib (CESA-2010:0616)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dbus-glib packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

dbus-glib is an add-on library to integrate the standard D-Bus library
with the GLib main loop and threading model. NetworkManager is a
network link manager that attempts to keep a wired or wireless network
connection active at all times.

It was discovered that dbus-glib did not enforce the 'access' flag on
exported GObject properties. If such a property were read/write
internally but specified as read-only externally, a malicious, local
user could use this flaw to modify that property of an application.
Such a change could impact the application's behavior (for example, if
an IP address were changed the network may not come up properly after
reboot) and possibly lead to a denial of service. (CVE-2010-1172)

Due to the way dbus-glib translates an application's XML definitions
of service interfaces and properties into C code at application build
time, applications built against dbus-glib that use read-only
properties needed to be rebuilt to fully fix the flaw. As such, this
update provides NetworkManager packages that have been rebuilt against
the updated dbus-glib packages. No other applications shipped with Red
Hat Enterprise Linux 5 were affected.

All dbus-glib and NetworkManager users are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue. Running instances of NetworkManager must be restarted (service
NetworkManager restart) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28789d3d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81163e7d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b1a2e96"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016901.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6062f1f5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-glib and / or networkmanager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-glib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-devel-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-glib-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-glib-devel-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"NetworkManager-gnome-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-glib-0.73-10.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-glib-devel-0.73-10.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
