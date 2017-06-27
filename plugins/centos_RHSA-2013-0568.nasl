#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0568 and 
# CentOS Errata and Security Advisory 2013:0568 respectively.
#

include("compat.inc");

if (description)
{
  script_id(64939);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/22 14:13:26 $");

  script_cve_id("CVE-2013-0292");
  script_bugtraq_id(57985);
  script_osvdb_id(90302);
  script_xref(name:"RHSA", value:"2013:0568");

  script_name(english:"CentOS 5 / 6 : dbus-glib (CESA-2013:0568)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dbus-glib packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

dbus-glib is an add-on library to integrate the standard D-Bus library
with the GLib main loop and threading model.

A flaw was found in the way dbus-glib filtered the message sender
(message source subject) when the 'NameOwnerChanged' signal was
received. This could trick a system service using dbus-glib (such as
fprintd) into believing a signal was sent from a privileged process,
when it was not. A local attacker could use this flaw to escalate
their privileges. (CVE-2013-0292)

All dbus-glib users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications linked against dbus-glib, such as fprintd and
NetworkManager, must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59b53144"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42999748"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2edbd7a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-glib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-glib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"dbus-glib-0.73-11.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-glib-devel-0.73-11.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"dbus-glib-0.86-6.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dbus-glib-devel-0.86-6.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
