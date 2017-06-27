#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-09.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14666);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772");
  script_osvdb_id(9407, 9408, 9409);
  script_xref(name:"GLSA", value:"200409-09");

  script_name(english:"GLSA-200409-09 : MIT krb5: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200409-09
(MIT krb5: Multiple vulnerabilities)

    The implementation of the Key Distribution Center (KDC) and the MIT krb5
    library contain double-free vulnerabilities, making client programs as well
    as application servers vulnerable.
    The ASN.1 decoder library is vulnerable to a denial of service attack,
    including the KDC.
  
Impact :

    The double-free vulnerabilities could allow an attacker to execute
    arbitrary code on a KDC host and hosts running krb524d or vulnerable
    services. In the case of a KDC host, this can lead to a compromise of the
    entire Kerberos realm. Furthermore, an attacker impersonating a legitimate
    KDC or application server can potentially execute arbitrary code on
    authenticating clients.
    An attacker can cause a denial of service for a KDC or application server
    and clients, the latter if impersonating a legitimate KDC or application
    server.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2004-002-dblfree.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34bb0fc8"
  );
  # http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2004-003-asn1.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d0e4d09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All mit-krb5 users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=app-crypt/mit-krb5-1.3.4'
    # emerge '>=app-crypt/mit-krb5-1.3.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mit-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/31");
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

if (qpkg_check(package:"app-crypt/mit-krb5", unaffected:make_list("ge 1.3.4"), vulnerable:make_list("lt 1.3.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MIT krb5");
}
