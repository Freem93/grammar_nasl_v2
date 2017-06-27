#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200512-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20313);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3671", "CVE-2005-3732");
  script_osvdb_id(60991, 61003);
  script_xref(name:"GLSA", value:"200512-04");

  script_name(english:"GLSA-200512-04 : Openswan, IPsec-Tools: Vulnerabilities in ISAKMP Protocol implementation");
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
"The remote host is affected by the vulnerability described in GLSA-200512-04
(Openswan, IPsec-Tools: Vulnerabilities in ISAKMP Protocol implementation)

    The Oulu University Secure Programming Group (OUSPG) discovered that
    various ISAKMP implementations, including Openswan and racoon (included
    in the IPsec-Tools package), behave in an anomalous way when they
    receive and handle ISAKMP Phase 1 packets with invalid or abnormal
    contents.
  
Impact :

    A remote attacker could craft specific packets that would result in a
    Denial of Service attack, if Openswan and racoon are used in specific,
    weak configurations.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ee.oulu.fi/research/ouspg/protos/testing/c09/isakmp/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200512-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Openswan users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/openswan-2.4.4'
    All IPsec-Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-firewall/ipsec-tools"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/openswan", unaffected:make_list("ge 2.4.4"), vulnerable:make_list("lt 2.4.4"))) flag++;
if (qpkg_check(package:"net-firewall/ipsec-tools", unaffected:make_list("ge 0.6.3", "rge 0.6.2-r1", "rge 0.4-r2"), vulnerable:make_list("lt 0.6.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Openswan / IPsec-Tools");
}
