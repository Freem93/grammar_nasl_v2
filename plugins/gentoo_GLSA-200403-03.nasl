#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200403-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14454);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0079", "CVE-2004-0081", "CVE-2004-0112");
  script_xref(name:"GLSA", value:"200403-03");

  script_name(english:"GLSA-200403-03 : Multiple OpenSSL Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200403-03
(Multiple OpenSSL Vulnerabilities)

    Testing performed by the OpenSSL group using the Codenomicon TLS Test
    Tool uncovered a NULL pointer assignment in the do_change_cipher_spec()
    function. A remote attacker could perform a carefully crafted SSL/TLS
    handshake against a server that used the OpenSSL library in such a way
    as to cause OpenSSL to crash. Depending on the application this could
    lead to a denial of service. All versions of OpenSSL from 0.9.6c to
    0.9.6l inclusive and from 0.9.7a to 0.9.7c inclusive are affected by
    this issue.
    A flaw has been discovered in SSL/TLS handshaking code when using
    Kerberos ciphersuites. A remote attacker could perform a carefully
    crafted SSL/TLS handshake against a server configured to use Kerberos
    ciphersuites in such a way as to cause OpenSSL to crash. Most
    applications have no ability to use Kerberos cipher suites and will
    therefore be unaffected. Versions 0.9.7a, 0.9.7b, and 0.9.7c of OpenSSL
    are affected by this issue.
    Testing performed by the OpenSSL group using the Codenomicon TLS Test
    Tool uncovered a bug in older versions of OpenSSL 0.9.6 that can lead
    to a Denial of Service attack (infinite loop). This issue was traced to
    a fix that was added to OpenSSL 0.9.6d some time ago. This issue will
    affect vendors that ship older versions of OpenSSL with backported
    security patches.
  
Impact :

    Although there are no public exploits known for bug, users are
    recommended to upgrade to ensure the security of their infrastructure.
  
Workaround :

    There is no immediate workaround; a software upgrade is required. The
    vulnerable function in the code has been rewritten."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200403-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users are recommened to upgrade openssl to either 0.9.7d or 0.9.6m:
    # emerge sync
    # emerge -pv '>=dev-libs/openssl-0.9.7d'
    # emerge '>=dev-libs/openssl-0.9.7d'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 0.9.7d", "eq 0.9.6m"), vulnerable:make_list("le 0.9.7c"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-libs/openssl");
}
