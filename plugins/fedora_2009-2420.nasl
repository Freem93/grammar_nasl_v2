#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-2420.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35801);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/11 13:16:07 $");

  script_cve_id("CVE-2009-0365", "CVE-2009-0578");
  script_bugtraq_id(33966);
  script_xref(name:"FEDORA", value:"2009-2420");

  script_name(english:"Fedora 9 : NetworkManager-openconnect-0.7.0.99-1.fc9 / NetworkManager-0.7.0.99-1.fc9 / etc (2009-2420)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora host is missing one or more security updates :

NetworkManager-0.7.0.99-1.fc9 :

  - Wed Mar 4 2009 Dan Williams <dcbw at redhat.com> -
    1:0.7.0.99-1

    - nm: make default wired 'Auto ethX' connection
      modifiable if an enabled system settings plugin
      supports modifying connections (rh #485555)

  - nm: manpage fixes (rh #447233)

    - nm: CVE-2009-0365 - GetSecrets disclosure

    - applet: CVE-2009-0578 - local users can modify the
      connection settings

    - applet: fix inability to choose WPA Ad-Hoc networks
      from the menu

    - ifcfg-rh: add read-only support for WPA-PSK
      connections

    - ifcfg-rh: revert fix for #441453 (honor localhost)
      until gdm gets fixed

    - Wed Feb 25 2009 Dan Williams <dcbw at redhat.com> -
      1:0.7.0.98-1.git20090225

    - Fix getting secrets for system connections (rh
      #486696)

    - More compatible modem autodetection

    - Better handle minimal ifcfg files

    - Mon Feb 23 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1:0.7.0.97-6.git20090220

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    - Fri Feb 20 2009 Dan Williams <dcbw at redhat.com> -
      1:0.7.0.97-5.git20090220

    - Use IFF_LOWER_UP for carrier detect instead of
      IFF_RUNNING

    - Add small delay before probing cdc-acm driven mobile
      broadband devices

    - Thu Feb 19 2009 Dan Williams <dcbw at redhat.com> -
      1:0.7.0.97-4.git20090219

    - Fix PEAP version selection in the applet (rh #468844)

    - Match hostname behavior to 'network' service when
      hostname is localhost (rh #441453)

    - Thu Feb 19 2009 Dan Williams <dcbw at redhat.com> -
      1:0.7.0.97-2

    - Fix 'noreplace' for nm-system-settings.conf

    - Wed Feb 18 2009 Dan Williams <dcbw at redhat.com> -
      1:0.7.0.97-1

    - Update to 0.7.1rc1

    - nm: support for Huawei E160G mobile broadband devices
      (rh #466177)

    - nm: fix misleading routing error message (rh #477916)

    - nm: fix issues with 32-character SSIDs (rh #485312)

    - nm: allow root to activate user connections

    - nm: automatic modem detection with udev-extras

    - nm: massive manpage rewrite

    - applet: fix crash when showing the CA certificate
      ignore dialog a second time

    - applet: clear keyring items when deleting a connection

    - applet: fix max signal strength calculation in menu
      (rh #475123)

    - applet: fix VPN export (rh #480496)

    - Sat Feb 7 2009 Dan Williams <dcbw at redhat.com> -
      1:0.7.0-2.git20090207

    - applet: fix blank VPN connection message bubbles

    - applet: better handling of VPN routing on update

    - applet: silence pointless warning (rh #484136)

    - applet: desensitize devices in the menu until they are
      ready (rh #483879)

    - nm: Expose WINS servers in the IP4Config over D-Bus

    - nm: Better handling of GSM Mobile Broadband modem
      initialization

    - nm: Handle DHCP Classless Static Routes (RFC 3442)

    - nm: Fix Mobile Broadband and PPPoE to always use
      'noauth'

    - nm: Better compatibility with older dual-SSID AP
      configurations (rh #445369)

    - nm: Mark nm-system-settings.conf as %config (rh
      #465633)

    - nm-tool: Show VPN connection information

    - ifcfg-rh: Silence message about ignoring loopback
      config (rh #484060)

    - ifcfg-rh: Fix issue with wrong gateway for system
      connections (rh #476089)

    - Fri Jan 2 2009 Dan Williams <dcbw at redhat.com> -
      1:0.7.0-1.git20090102

[plus 131 lines in the Changelog]

NetworkManager-openconnect-0.7.0.99-1.fc9 :

  - Bug #487722 - CVE-2009-0365 NetworkManager: GetSecrets
    disclosure

  - Bug #487752 - CVE-2009-0578 NetworkManager: local users
    can modify the connection settings

NetworkManager-pptp-0.7.0.99-1.fc9 :

  - Thu Mar 5 2009 Dan Williams <dcbw at redhat.com>
    1:0.7.0.99-1

    - Update to 0.7.1rc3

    - Mon Feb 23 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1:0.7.0.97-2

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    - Thu Feb 19 2009 Dan Williams <dcbw at redhat.com>
      1:0.7.0.97-1

    - Update to 0.7.1rc1

    - Set a reasonable MTU

    - Ensure 'noauth' is used

    - Fix domain-based logins

    - Fix saving MPPE values in connection editor

    - Sat Jan 3 2009 Dan Williams <dcbw at redhat.com>
      1:0.7.0-1.svn16

    - Rebuild for updated NetworkManager

    - Fix some specfile issues (rh #477153)

    - Allow the EAP authentication method

NetworkManager-openvpn-0.7.0.99-1.fc9 :

  - Thu Mar 5 2009 Dan Williams <dcbw at redhat.com>
    1:0.7.0.99-1

    - Update to 0.7.1rc3

    - Mon Feb 23 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1:0.7.0.97-2

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    - Thu Feb 19 2009 Dan Williams <dcbw at redhat.com>
      1:0.7.0.97-1

    - Update to 0.7.1rc1

    - Handle HMAC Authentication (--auth)

    - Handle TAP device subnet masks correctly

    - Don't segfault if the connection type is invalid

    - Sat Jan 3 2009 Dan Williams <dcbw at redhat.com>
      1:0.7.0-18.svn11

    - Rebuild for updated NetworkManager

    - Fix some specfile issues (rh #477149)

    - Sat Dec 20 2008 Christoph Hoger <choeger at
      cs.tu-berlin.de> 0.7.0-17.svn4326

    - removed libpng-devel from BuildRequires, added
      /usr/share/gnome-vpn-properties/openvpn/ (rh #477149)

    - Fri Nov 21 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-16.svn4326

    - Rebuild for updated NetworkManager

    - Mon Oct 27 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-16.svn4229

    - Rebuild for updated NetworkManager

    - Sun Oct 12 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-16.svn4175

    - Rebuild for updated NetworkManager

    - Allow changing passwords from the connection editor

    - Honor OpenVPN's 'route-vpn-gateway' option

    - Tue Sep 30 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-16.svn4027

    - Fix order of Password TLS certificate choosers (rh
      #464765)

    - Use /usr/lib/rpm/find-lang.sh
      /var/tmp/NetworkManager-openvpn-0.7.0.99-root for
      locale-specific files (rh #448551)

    - Fix --script-security issues with OpenVPN 2.1-rc9 and
      later (rh #460754)

    - Fri Aug 29 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-15.svn4027

    - Rebuild for updated NetworkManager

    - Mon Aug 11 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-15.svn3930

    - Rebuild for updated NetworkManager

    - Thu Jul 24 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-15.svn3846

    - Rebuild to sync with F9 release number

    - Thu Jul 24 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-11.svn3846

    - Fix TLS Authentication direction combo

    - Only update settings if the advanced dialog's OK
      button is pressed

    - Fri Jul 18 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-11.svn3832

    - Update for NM netmask -> prefix changes

    - Wed Jul 2 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-11.svn3801

    - Update for moving VPN editing into connection manager

    - Import OpenVPN configuration files rather than old
      custom format

    - Tue Jun 24 2008 Christoph Hoger <choeger at
      cs.tu-berlin.de> 1:0.7.0-14.svn3632

    - revoke last change

    - openvpn seems to be buggy itself

    - Fri Jun 13 2008 Christoph Hoger <choeger at
      cs.tu-berlin.de> 1:0.7.0-13.svn3632

    - Fix getting remote ip

    - fixes #446335

NetworkManager-vpnc-0.7.0.99-1.fc9 :

  - Thu Mar 5 2009 Dan Williams <dcbw at redhat.com>
    1:0.7.0.99-1

    - Update to 0.7.1rc3

    - Mon Feb 23 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1:0.7.0.97-2

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    - Thu Feb 19 2009 Dan Williams <dcbw at redhat.com>
      1:0.7.0.97-1

    - Update to 0.7.1rc1

    - Handle import/export of 'EnableNat', 'DHGroup',
      'SaveUserPassword', and 'EnableLocalLAN'

    - Sat Jan 3 2009 Dan Williams <dcbw at redhat.com>
      1:0.7.0-1

    - Rebuild for updated NetworkManager

    - Better handling of passwords that shouldn't be saved

    - Fix some specfile issues (rh #477151)

    - Fri Nov 21 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-0.11.svn4326

    - Rebuild for updated NetworkManager

    - Tue Nov 18 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-0.11.svn4296

    - Rebuild for updated NetworkManager

    - Mon Nov 17 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-0.11.svn4293

    - Ensure errors are shown when connection fails (rh
      #331141)

    - Fix failures to ask for passwords on connect (rh
      #429287)

    - Fix routing when concentrator specifies routes (rh
      #449283)

    - Pull in upstream support for tokens and not saving
      passwords

    - Mon Oct 27 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-0.11.svn4229

    - Rebuild for updated NetworkManager

    - Tue Oct 14 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-11.svn4175

    - Fix password issue with configurations that don't save
      the user password in the keyring (rh #466864)

  - Sun Oct 12 2008 Dan Williams <dcbw at redhat.com>
    1:0.7.0-10.svn4175

    - Rebuild for updated NetworkManager

    - Allow changing passwords from the connection editor

    - Fri Aug 29 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-10.svn4024

    - Fix regression where username radio buttons were
      mistakenly shown in the auth dialog

  - Fix regression where the auth dialog would segfault when
    cancel was clicked

    - Wed Aug 27 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-10.svn4022

    - Rebuild for updated NetworkManager

    - Mon Aug 11 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-10.svn3928

    - Rebuild for updated NetworkManager

    - Thu Jul 24 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-10.svn3846

    - Rebuild for updated NetworkManager

    - Fri Jul 18 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-10.svn3832

    - Update for NM netmask -> prefix changes

    - Wed Jul 2 2008 Dan Williams <dcbw at redhat.com>
      1:0.7.0-10.svn3801

    - Update for moving VPN editing into connection manager

    - Add option to disable Dead Peer Detection

    - Add option to select NAT Traversal mode

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=487722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=487752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/020990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a846b44"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/020991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e845fc10"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/020992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35f0eb63"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/020993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5af8bee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/020994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c28012d8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-openconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-pptp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:NetworkManager-vpnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"NetworkManager-0.7.0.99-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"NetworkManager-openconnect-0.7.0.99-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"NetworkManager-openvpn-0.7.0.99-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"NetworkManager-pptp-0.7.0.99-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"NetworkManager-vpnc-0.7.0.99-1.fc9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-openconnect / etc");
}
