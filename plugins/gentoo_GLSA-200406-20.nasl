#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200406-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14531);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0590");
  script_osvdb_id(7281);
  script_xref(name:"GLSA", value:"200406-20");

  script_name(english:"GLSA-200406-20 : FreeS/WAN, Openswan, strongSwan: Vulnerabilities in certificate handling");
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
"The remote host is affected by the vulnerability described in GLSA-200406-20
(FreeS/WAN, Openswan, strongSwan: Vulnerabilities in certificate handling)

    All these IPsec implementations have several bugs in the
    verify_x509cert() function, which performs certificate validation, that
    make them vulnerable to malicious PKCS#7 wrapped objects.
  
Impact :

    With a carefully crafted certificate payload an attacker can
    successfully authenticate against FreeS/WAN, Openswan, strongSwan or
    Super-FreeS/WAN, or make the daemon go into an endless loop.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.openswan.org/pipermail/dev/2004-June/000370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200406-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All FreeS/WAN 1.9x users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '=net-misc/freeswan-1.99-r1'
    # emerge '=net-misc/freeswan-1.99-r1'
    All FreeS/WAN 2.x users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=net-misc/freeswan-2.04-r1'
    # emerge '>=net-misc/freeswan-2.04-r1'
    All Openswan 1.x users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '=net-misc/openswan-1.0.6_rc1'
    # emerge '=net-misc/openswan-1.0.6_rc1'
    All Openswan 2.x users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=net-misc/openswan-2.1.4'
    # emerge '>=net-misc/openswan-2.1.4'
    All strongSwan users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=net-misc/strongswan-2.1.3'
    # emerge '>=net-misc/strongswan-2.1.3'
    All Super-FreeS/WAN users should migrate to the latest stable version
    of Openswan. Note that Portage will force a move for Super-FreeS/WAN
    users to Openswan.
    # emerge sync
    # emerge -pv '=net-misc/openswan-1.0.6_rc1'
    # emerge '=net-misc/openswan-1.0.6_rc1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:freeswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:super-freeswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/freeswan", unaffected:make_list("ge 2.04-r1", "eq 1.99-r1"), vulnerable:make_list("lt 2.04-r1"))) flag++;
if (qpkg_check(package:"net-misc/openswan", unaffected:make_list("ge 2.1.4", "eq 1.0.6_rc1"), vulnerable:make_list("lt 2.1.4"))) flag++;
if (qpkg_check(package:"net-misc/super-freeswan", unaffected:make_list(), vulnerable:make_list("le 1.99.7.3"))) flag++;
if (qpkg_check(package:"net-misc/strongswan", unaffected:make_list("ge 2.1.3"), vulnerable:make_list("lt 2.1.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "FreeS/WAN / Openswan / strongSwan");
}
