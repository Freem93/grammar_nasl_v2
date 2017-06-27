#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200406-21.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14532);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0523");
  script_osvdb_id(6846);
  script_xref(name:"GLSA", value:"200406-21");

  script_name(english:"GLSA-200406-21 : mit-krb5: Multiple buffer overflows in krb5_aname_to_localname");
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
"The remote host is affected by the vulnerability described in GLSA-200406-21
(mit-krb5: Multiple buffer overflows in krb5_aname_to_localname)

    The library function krb5_aname_to_localname() contains multiple buffer
    overflows. This is only exploitable if explicit mapping or rules-based
    mapping is enabled. These are not enabled as default.
    With explicit mapping enabled, an attacker must authenticate using a
    principal name listed in the explicit mapping list.
    With rules-based mapping enabled, an attacker must first be able to create
    arbitrary principal names either in the local realm Kerberos realm or in a
    remote realm from which the local realm's service are reachable by
    cross-realm authentication.
  
Impact :

    An attacker could use these vulnerabilities to execute arbitrary code with
    the permissions of the user running mit-krb5, which could be the root user.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version."
  );
  # http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2004-001-an_to_ln.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c54187f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200406-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"mit-krb5 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=app-crypt/mit-krb5-1.3.3-r1'
    # emerge '>=app-crypt/mit-krb5-1.3.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mit-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/01");
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

if (qpkg_check(package:"app-crypt/mit-krb5", unaffected:make_list("ge 1.3.3-r1"), vulnerable:make_list("le 1.3.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mit-krb5");
}
