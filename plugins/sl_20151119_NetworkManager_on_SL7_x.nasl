#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87548);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-0272", "CVE-2015-2924");

  script_name(english:"Scientific Linux Security Update : NetworkManager on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that NetworkManager would set device MTUs based on
MTU values received in IPv6 RAs (Router Advertisements), without
sanity checking the MTU value first. A remote attacker could exploit
this flaw to create a denial of service attack, by sending a specially
crafted IPv6 RA packet to disturb IPv6 communication. (CVE-2015-0272)

A flaw was found in the way NetworkManager handled router
advertisements. An unprivileged user on a local network could use IPv6
Neighbor Discovery ICMP to broadcast a non-route with a low hop limit,
causing machines to lower the hop limit on existing IPv6 routes. If
this limit is small enough, IPv6 packets would be dropped before
reaching the final destination. (CVE-2015-2924)

The network-manager-applet and NetworkManager-libreswan packages have
been upgraded to upstream versions 1.0.6, and provide a number of bug
fixes and enhancements over the previous versions.

Bugs :

  - It was not previously possible to set the Wi-Fi band to
    the 'a' or 'bg' values to lock to a specific frequency
    band. NetworkManager has been fixed, and it now sets the
    wpa_supplicant's 'freq_list' option correctly, which
    enables proper Wi-Fi band locking.

  - NetworkManager immediately failed activation of devices
    that did not have a carrier early in the boot process.
    The legacy network.service then reported activation
    failure. Now, NetworkManager has a grace period during
    which it waits for the carrier to appear. Devices that
    have a carrier down for a short time on system startup
    no longer cause the legacy network.service to fail.

  - NetworkManager brought down a team device if the teamd
    service managing it exited unexpectedly, and the team
    device was deactivated. Now, NetworkManager respawns the
    teamd instances that disappear and is able to recover
    from a teamd failure avoiding disruption of the team
    device operation.

  - NetworkManager did not send the FQDN DHCP option even if
    host name was set to FQDN. Consequently, Dynamic DNS
    (DDNS) setups failed to update the DNS records for
    clients running NetworkManager. Now, NetworkManager
    sends the FQDN option with DHCP requests, and the DHCP
    server is able to create DNS records for such clients.

  - The command-line client was not validating the
    vlan.flags property correctly, and a spurious warning
    message was displayed when the nmcli tool worked with
    VLAN connections. The validation routine has been fixed,
    and the warning message no longer appears.

  - NetworkManager did not propagate a media access control
    (MAC) address change from a bonding interface to a VLAN
    interface on top of it. Consequently, a VLAN interface
    on top of a bond used an incorrect MAC address. Now,
    NetworkManager synchronizes the addresses correctly.

Enhancements :

  - IPv6 Privacy extensions are now enabled by default.
    NetworkManager checks the per-network configuration
    files, NetworkManager.conf, and then falls back to
    '/proc/sys/net/ipv6/conf/default/use_tempaddr' to
    determine and set IPv6 privacy settings at device
    activation.

  - The NetworkManager command-line tool, nmcli, now allows
    setting the wake-on-lan property to 0 ('none',
    'disable', 'disabled').

  - NetworkManager now provides information about metered
    connections.

  - NetworkManager daemon and the connection editor now
    support setting the Maximum Transmission Unit (MTU) of a
    bond. It is now possible to change MTU of a bond
    interface in a GUI.

  - NetworkManager daemon and the connection editor now
    support setting the MTU of a team, allowing to change
    MTU of a teaming interface."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=8368
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5094cb6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ModemManager-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ModemManager-debuginfo-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ModemManager-devel-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ModemManager-glib-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ModemManager-glib-devel-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ModemManager-vala-1.1.0-8.git20130913.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-adsl-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-config-routing-rules-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-config-server-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-debuginfo-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-devel-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-glib-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libnm-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libreswan-1.0.6-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libreswan-debuginfo-1.0.6-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libreswan-gnome-1.0.6-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-team-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-tui-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-wifi-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-wwan-1.0.6-27.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnm-gtk-1.0.6-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnm-gtk-devel-1.0.6-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"network-manager-applet-1.0.6-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"network-manager-applet-debuginfo-1.0.6-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nm-connection-editor-1.0.6-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
