#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14470);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200404-05");

  script_name(english:"GLSA-200404-05 : ipsec-tools contains an X.509 certificates vulnerability.");
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
"The remote host is affected by the vulnerability described in GLSA-200404-05
(ipsec-tools contains an X.509 certificates vulnerability.)

    racoon (a utility in the ipsec-tools package) does not verify digital
    signatures on Phase1 packets.  This means  that anybody holding the correct
    X.509 certificate would be able to establish a connection, even if they did
    not have the corresponding private key.
  
Impact :

    Since digital signatures are not verified by the racoon tool, an attacker may
	be able to connect to the VPN gateway and/or execute a man-in-the-middle attack.
  
Workaround :

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"ipsec-tools users should upgrade to version 0.2.5 or later:
    # emerge sync
    # emerge -pv '>=net-firewall/ipsec-tools-0.2.5'
    # emerge '>=net-firewall/ipsec-tools-0.2.5'"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(amd64)$") audit(AUDIT_ARCH_NOT, "amd64", ourarch);

flag = 0;

if (qpkg_check(package:"net-firewall/ipsec-tools", arch:"amd64", unaffected:make_list("ge 0.2.5"), vulnerable:make_list("le 0.2.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-firewall/ipsec-tools");
}
