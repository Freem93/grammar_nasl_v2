#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-30.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(28319);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2006-7227", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");
  script_osvdb_id(40753, 40754, 40755, 40756, 40757, 40758, 40759, 40760, 40763, 40766);
  script_xref(name:"GLSA", value:"200711-30");

  script_name(english:"GLSA-200711-30 : PCRE: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200711-30
(PCRE: Multiple vulnerabilities)

    Tavis Ormandy (Google Security) discovered multiple vulnerabilities in
    PCRE. He reported an error when processing '\\Q\\E' sequences with
    unmatched '\\E' codes that can lead to the compiled bytecode being
    corrupted (CVE-2007-1659). PCRE does not properly calculate sizes for
    unspecified 'multiple forms of character class', which triggers a
    buffer overflow (CVE-2007-1660). Further improper calculations of
    memory boundaries were reported when matching certain input bytes
    against regex patterns in non UTF-8 mode (CVE-2007-1661) and when
    searching for unmatched brackets or parentheses (CVE-2007-1662).
    Multiple integer overflows when processing escape sequences may lead to
    invalid memory read operations or potentially cause heap-based buffer
    overflows (CVE-2007-4766). PCRE does not properly handle '\\P' and
    '\\P{x}' sequences which can lead to heap-based buffer overflows or
    trigger the execution of infinite loops (CVE-2007-4767), PCRE is also
    prone to an error when optimizing character classes containing a
    singleton UTF-8 sequence which might lead to a heap-based buffer
    overflow (CVE-2007-4768).
    Chris Evans also reported multiple integer overflow vulnerabilities in
    PCRE when processing a large number of named subpatterns ('name_count')
    or long subpattern names ('max_name_size') (CVE-2006-7227), and via
    large 'min', 'max', or 'duplength' values (CVE-2006-7228) both possibly
    leading to buffer overflows. Another vulnerability was reported when
    compiling patterns where the '-x' or '-i' UTF-8 options change within
    the pattern, which might lead to improper memory calculations
    (CVE-2006-7230).
  
Impact :

    An attacker could exploit these vulnerabilities by sending specially
    crafted regular expressions to applications making use of the PCRE
    library, which could possibly lead to the execution of arbitrary code,
    a Denial of Service or the disclosure of sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PCRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/libpcre-7.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libpcre");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
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

if (qpkg_check(package:"dev-libs/libpcre", unaffected:make_list("ge 7.3-r1"), vulnerable:make_list("lt 7.3-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PCRE");
}
