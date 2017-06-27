#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200904-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(36139);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-5397", "CVE-2008-5398", "CVE-2009-0414", "CVE-2009-0936", "CVE-2009-0937", "CVE-2009-0938", "CVE-2009-0939");
  script_bugtraq_id(33399);
  script_osvdb_id(54021, 54022, 54023, 54024);
  script_xref(name:"GLSA", value:"200904-11");

  script_name(english:"GLSA-200904-11 : Tor: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200904-11
(Tor: Multiple vulnerabilities)

    Theo de Raadt reported that the application does not properly drop
    privileges to the primary groups of the user specified via the 'User'
    configuration option (CVE-2008-5397).
    rovv reported that the 'ClientDNSRejectInternalAddresses' configuration
    option is not always enforced (CVE-2008-5398).
    Ilja van Sprundel reported a heap-corruption vulnerability that might
    be remotely triggerable on some platforms (CVE-2009-0414).
    It has been reported that incomplete IPv4 addresses are treated as
    valid, violating the specification (CVE-2009-0939).
    Three unspecified vulnerabilities have also been reported
    (CVE-2009-0936, CVE-2009-0937, CVE-2009-0938).
  
Impact :

    A local attacker could escalate privileges by leveraging unintended
    supplementary group memberships of the Tor process. A remote attacker
    could exploit these vulnerabilities to cause a heap corruption with
    unknown impact and attack vectors, to cause a Denial of Service via CPU
    consuption or daemon crash, and to weaken anonymity provided by the
    service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200904-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Tor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/tor-0.2.0.34'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/tor", unaffected:make_list("ge 0.2.0.34"), vulnerable:make_list("lt 0.2.0.34"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Tor");
}
