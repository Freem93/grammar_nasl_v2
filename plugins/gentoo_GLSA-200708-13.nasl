#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200708-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25919);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/08/31 14:21:56 $");

  script_cve_id("CVE-2007-2925", "CVE-2007-2926");
  script_osvdb_id(36235, 36236);
  script_xref(name:"GLSA", value:"200708-13");

  script_name(english:"GLSA-200708-13 : BIND: Weak random number generation");
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
"The remote host is affected by the vulnerability described in GLSA-200708-13
(BIND: Weak random number generation)

    Amit Klein from Trusteer reported that the random number generator of
    ISC BIND leads, half the time, to predictable (1 chance to 8) query IDs
    in the resolver routine or in zone transfer queries (CVE-2007-2926).
    Additionally, the default configuration file has been strengthen with
    respect to the allow-recursion{} and the allow-query{} options
    (CVE-2007-2925).
  
Impact :

    A remote attacker can use this weakness by sending queries for a domain
    he handles to a resolver (directly to a recursive server, or through
    another process like an email processing) and then observing the
    resulting IDs of the iterative queries. The attacker will half the time
    be able to guess the next query ID, then perform cache poisoning by
    answering with those guessed IDs, while spoofing the UDP source address
    of the reply. Furthermore, with empty allow-recursion{} and
    allow-query{} options, the default configuration allowed anybody to
    make recursive queries and query the cache.
  
Workaround :

    There is no known workaround at this time for the random generator
    weakness. The allow-recursion{} and allow-query{} options should be set
    to trusted hosts only in /etc/bind/named.conf, thus preventing several
    security risks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200708-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ISC BIND users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/bind-9.4.1_p1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-dns/bind", unaffected:make_list("ge 9.4.1_p1"), vulnerable:make_list("lt 9.4.1_p1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BIND");
}
