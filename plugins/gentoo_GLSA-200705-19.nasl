#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200705-19.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25340);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2007-1001", "CVE-2007-1285", "CVE-2007-1286", "CVE-2007-1484", "CVE-2007-1521", "CVE-2007-1583", "CVE-2007-1700", "CVE-2007-1701", "CVE-2007-1711", "CVE-2007-1717", "CVE-2007-1718", "CVE-2007-1864", "CVE-2007-1900", "CVE-2007-2509", "CVE-2007-2510", "CVE-2007-2511");
  script_osvdb_id(32769, 32771, 33936, 33938, 33940, 33944, 33945, 33946, 33948, 33962, 34671, 34672, 34674, 34675, 34676);
  script_xref(name:"GLSA", value:"200705-19");

  script_name(english:"GLSA-200705-19 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200705-19
(PHP: Multiple vulnerabilities)

    Several vulnerabilities were found in PHP, most of them during the
    Month Of PHP Bugs (MOPB) by Stefan Esser. The most severe of these
    vulnerabilities are integer overflows in wbmp.c from the GD library
    (CVE-2007-1001) and in the substr_compare() PHP 5 function
    (CVE-2007-1375). Ilia Alshanetsky also reported a buffer overflow in
    the make_http_soap_request() and in the user_filter_factory_create()
    functions (CVE-2007-2510, CVE-2007-2511), and Stanislav Malyshev
    discovered another buffer overflow in the bundled XMLRPC library
    (CVE-2007-1864). Additionally, the session_regenerate_id() and the
    array_user_key_compare() functions contain a double-free vulnerability
    (CVE-2007-1484, CVE-2007-1521). Finally, there exist implementation
    errors in the Zend engine, in the mb_parse_str(), the unserialize() and
    the mail() functions and other elements.
  
Impact :

    Remote attackers might be able to exploit these issues in PHP
    applications making use of the affected functions, potentially
    resulting in the execution of arbitrary code, Denial of Service,
    execution of scripted contents in the context of the affected site,
    security bypass or information leak.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200705-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.2'
    All PHP 4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/php-4.4.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("rge 4.4.7", "rge 4.4.8_pre20070816", "ge 5.2.2"), vulnerable:make_list("lt 5.2.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
