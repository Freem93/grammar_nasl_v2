#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2581 and 
# Oracle Linux Security Advisory ELSA-2016-2581 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94703);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/11 14:36:26 $");

  script_cve_id("CVE-2016-0764");
  script_osvdb_id(136861);
  script_xref(name:"RHSA", value:"2016:2581");

  script_name(english:"Oracle Linux 7 : NetworkManager (ELSA-2016-2581)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2581 :

An update for NetworkManager is now available for Red Hat Enterprise
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006473.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected networkmanager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libreswan-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnm-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnm-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnma-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nm-connection-editor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-adsl-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-config-server-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-dispatcher-routing-rules-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-glib-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libnm-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libreswan-1.2.4-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-libreswan-gnome-1.2.4-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-team-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-tui-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-wifi-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"NetworkManager-wwan-1.4.0-12.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-3.2.28-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-cli-3.2.28-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-devel-3.2.28-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnl3-doc-3.2.28-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnm-gtk-1.4.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnm-gtk-devel-1.4.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnma-1.4.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libnma-devel-1.4.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"network-manager-applet-1.4.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nm-connection-editor-1.4.0-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc");
}
