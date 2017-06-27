#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2581 and 
# CentOS Errata and Security Advisory 2016:2581 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95328);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/11/28 15:05:43 $");

  script_cve_id("CVE-2016-0764");
  script_osvdb_id(136861);
  script_xref(name:"RHSA", value:"2016:2581");

  script_name(english:"CentOS 7 : NetworkManager / NetworkManager-libreswan / libnl3 / network-manager-applet (CESA-2016:2581)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for NetworkManager is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

NetworkManager is a system network service that manages network
devices and connections, attempting to keep active network
connectivity when available. Its capabilities include managing
Ethernet, wireless, mobile broadband (WWAN), and PPPoE devices, as
well as providing VPN integration with a variety of different VPN
services.

The following packages have been upgraded to a newer upstream version:
NetworkManager (1.4.0), NetworkManager-libreswan (1.2.4),
network-manager-applet (1.4.0), libnl3 (3.2.28). (BZ#1264552,
BZ#1296058, BZ#1032717, BZ#1271581)

Security Fix(es) :

* A race condition vulnerability was discovered in NetworkManager.
Temporary files were created insecurely when saving or updating
connection settings, which could allow local users to read connection
secrets such as VPN passwords or WiFi keys. (CVE-2016-0764)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?180a7306"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c0dcd72"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a818611"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81f9c92a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-libreswan-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnl3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnl3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnl3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnm-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnm-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnma-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nm-connection-editor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-adsl-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-config-server-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-dispatcher-routing-rules-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-glib-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libnm-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libreswan-1.2.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-libreswan-gnome-1.2.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-team-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-tui-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-wifi-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"NetworkManager-wwan-1.4.0-12.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnl3-3.2.28-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnl3-cli-3.2.28-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnl3-devel-3.2.28-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnl3-doc-3.2.28-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnm-gtk-1.4.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnm-gtk-devel-1.4.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnma-1.4.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libnma-devel-1.4.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"network-manager-applet-1.4.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nm-connection-editor-1.4.0-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
