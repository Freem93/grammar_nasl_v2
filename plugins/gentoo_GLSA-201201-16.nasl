#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201201-16.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(57722);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2012-0064");
  script_bugtraq_id(51562);
  script_osvdb_id(78445);
  script_xref(name:"GLSA", value:"201201-16");

  script_name(english:"GLSA-201201-16 : X.Org X Server/X Keyboard Configuration Database: Screen lock bypass");
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
"The remote host is affected by the vulnerability described in GLSA-201201-16
(X.Org X Server/X Keyboard Configuration Database: Screen lock bypass)

    Starting with the =x11-base/xorg-server-1.11 package, the X.Org X Server
      again provides debugging functionality that can be used terminate an
      application that exclusively grabs mouse and keyboard input, like screen
      locking utilities.
    Gu1 reported that the X Keyboard Configuration Database maps this
      functionality by default to the Ctrl+Alt+Numpad * key combination.
  
Impact :

    A physically proximate attacker could exploit this vulnerability to gain
      access to a locked X session without providing the correct credentials.
  
Workaround :

    Downgrade to any version of x11-base/xorg-server below
      x11-base/xorg-server-1.11:
      # emerge --oneshot --verbose '<x11-base/xorg-server-1.11'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201201-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All xkeyboard-config users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=x11-misc/xkeyboard-config-2.4.1-r3'
    NOTE: The X.Org X Server 1.11 was only stable on the AMD64, ARM, HPPA,
      and x86 architectures. Users of the stable branches of all other
      architectures are not affected and will be directly provided with a fixed
      X Keyboard Configuration Database version."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(amd64|arm|hppa|x86)$") audit(AUDIT_ARCH_NOT, "amd64|arm|hppa|x86", ourarch);

flag = 0;

if (qpkg_check(package:"x11-misc/xkeyboard-config", arch:"amd64 arm hppa x86", unaffected:make_list("ge 2.4.1-r3"), vulnerable:make_list("lt 2.4.1-r3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X.Org X Server/X Keyboard Configuration Database");
}
