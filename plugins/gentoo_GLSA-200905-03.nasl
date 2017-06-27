#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200905-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(38884);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/28 18:42:39 $");

  script_cve_id("CVE-2009-1574", "CVE-2009-1632");
  script_osvdb_id(54286, 56400, 56401);
  script_xref(name:"GLSA", value:"200905-03");

  script_name(english:"GLSA-200905-03 : IPSec Tools: Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-200905-03
(IPSec Tools: Denial of Service)

    The following vulnerabilities have been found in the racoon daemon as
    shipped with IPSec Tools:
    Neil Kettle reported that
    racoon/isakmp_frag.c is prone to a NULL pointer dereference
    (CVE-2009-1574).
    Multiple memory leaks exist in (1) the
    eay_check_x509sign() function in racoon/crypto_openssl.c and (2)
    racoon/nattraversal.c (CVE-2009-1632).
  
Impact :

    A remote attacker could send specially crafted fragmented ISAKMP
    packets without a payload or exploit vectors related to X.509
    certificate authentication and NAT traversal, possibly resulting in a
    crash of the racoon daemon.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200905-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All IPSec Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-firewall/ipsec-tools-0.7.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
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

if (qpkg_check(package:"net-firewall/ipsec-tools", unaffected:make_list("ge 0.7.2"), vulnerable:make_list("lt 0.7.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IPSec Tools");
}
