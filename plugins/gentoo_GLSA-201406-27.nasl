#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201406-27.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(76271);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/13 14:27:08 $");

  script_cve_id("CVE-2013-4288", "CVE-2013-4311", "CVE-2013-4324", "CVE-2013-4325", "CVE-2013-4327");
  script_bugtraq_id(62499, 62503, 62508, 62511, 62538);
  script_xref(name:"GLSA", value:"201406-27");

  script_name(english:"GLSA-201406-27 : polkit, Spice-Gtk, systemd, HPLIP, libvirt: Privilege escalation");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201406-27
(polkit, Spice-Gtk, systemd, HPLIP, libvirt: Privilege escalation)

    polkit has a race condition which potentially allows a process to change
      its UID/EUID via suid or pkexec before authentication is completed.
  
Impact :

    A local attacker could start a suid or pkexec process through a
      polkit-enabled application, which could result in privilege escalation or
      bypass of polkit restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201406-27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All polkit users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-auth/polkit-0.112'
    All HPLIP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-print/hplip-3.14.1'
    All Spice-Gtk users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/spice-gtk-0.21'
    All systemd users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-apps/systemd-204-r1'
    All libvirt users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/libvirt-1.1.2-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"sys-apps/systemd", unaffected:make_list("ge 204-r1"), vulnerable:make_list("lt 204-r1"))) flag++;
if (qpkg_check(package:"sys-auth/polkit", unaffected:make_list("ge 0.112"), vulnerable:make_list("lt 0.112"))) flag++;
if (qpkg_check(package:"net-print/hplip", unaffected:make_list("ge 3.14.1"), vulnerable:make_list("lt 3.14.1"))) flag++;
if (qpkg_check(package:"net-misc/spice-gtk", unaffected:make_list("ge 0.21"), vulnerable:make_list("lt 0.21"))) flag++;
if (qpkg_check(package:"app-emulation/libvirt", unaffected:make_list("ge 1.1.2-r3"), vulnerable:make_list("lt 1.1.2-r3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "polkit / Spice-Gtk / systemd / HPLIP / libvirt");
}
