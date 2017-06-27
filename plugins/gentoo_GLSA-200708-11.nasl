#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200708-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25917);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:23 $");

  script_cve_id("CVE-2007-3946", "CVE-2007-3947", "CVE-2007-3948", "CVE-2007-3949", "CVE-2007-3950");
  script_osvdb_id(38308, 38309, 38310, 38311, 38312, 38313, 38314, 38315, 38316, 38317, 38318);
  script_xref(name:"GLSA", value:"200708-11");

  script_name(english:"GLSA-200708-11 : Lighttpd: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200708-11
(Lighttpd: Multiple vulnerabilities)

    Stefan Esser discovered errors with evidence of memory corruption in
    the code parsing the headers. Several independent researchers also
    reported errors involving the handling of HTTP headers, the mod_auth
    and mod_scgi modules, and the limitation of active connections.
  
Impact :

    A remote attacker can trigger any of these vulnerabilities by sending
    malicious data to the server, which may lead to a crash or memory
    exhaustion, and potentially the execution of arbitrary code.
    Additionally, access-deny settings can be evaded by appending a final /
    to a URL.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200708-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Lighttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/lighttpd-1.4.16'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/15");
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

if (qpkg_check(package:"www-servers/lighttpd", unaffected:make_list("ge 1.4.16"), vulnerable:make_list("lt 1.4.16"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Lighttpd");
}
