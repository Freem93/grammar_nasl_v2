#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8612.
#

include("compat.inc");

if (description)
{
  script_id(55842);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-2176");
  script_bugtraq_id(48396);
  script_xref(name:"FEDORA", value:"2011-8612");

  script_name(english:"Fedora 14 : NetworkManager-0.8.4-2.git20110622.fc14 (2011-8612)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the security issue for creating shared WiFi
networks. It's been tracked by #709662 - CVE-2011-2176.

Before this update, NetworkManager didn't respect PolicyKit policies
for creating shared WiFi networks: actions
org.freedesktop.network-manager-settings.system.wifi.share.open and
org.freedesktop.network-manager-settings.system.wifi.share.protected
in
/usr/share/polkit-1/actions/org.freedesktop.network-manager-settings.s
ystem.policy file. Thus, users could create shared WiFi networks even
if it was disabled via the PolicyKit setting. This update fixes this
issue. Be aware, that the default policies still allow creating shared
WiFi networks. You should modify <allow_active>yes</allow_active> to
<allow_active>auth_admin</allow_active> if you require authorization
with root password, or to <allow_active>no</allow_active> to disallow
creating the networks altogether through the above PolicyKit actions.

In addition, this update fixes other bugs by updating NetworkManager
to git snaphot as of 2011-06-22.

  - core: fix up checks for s390 CTC device type (bgo
    #649025)

    - core: recognize platform 'gadget' devices

    - core: only send hostname without domain as host-name
      option (rh #694758)

    - core: clear 'invalid' connection tag when cable is
      re-plugged

    - core: fix crash requesting system VPN secrets (bgo
      #651710)

    - core: add MAC address blacklisting feature for WiFi
      and ethernet connections

    - core: allow _ as a valid character for GSM APNs

    - wifi: always fix up Ad-Hoc frequency when connecting
      (rh #699203)

    - keyfile: better handle cert/key files that don't exist
      (bgo #649807)

    - keyfile: ignore .pem and .der file changes

    - editor: improve usability for entering manual IP
      addresses and routes (rh #698199) (bgo #607678)

    - editor: don't crash in edit_done_cb() when connection
      is invalid (rh #704848)

    - editor: don't allow inserting 0.0.0.0 as destination
      and netmask for IPv4 routes

    - editor: allow _ as a valid character for GSM APNs

    - applet: ensure entries activate default button if
      Enter is pressed (rh #622487)

    - applet: add gsm registration status notification

    - applet: filter APN entry characters in mobile-wizard

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=709662"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94b66e11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2269d34c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected NetworkManager package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"NetworkManager-0.8.4-2.git20110622.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager");
}
