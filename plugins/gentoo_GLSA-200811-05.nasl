#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200811-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(34787);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-0599", "CVE-2008-0674", "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-2371", "CVE-2008-2665", "CVE-2008-2666", "CVE-2008-2829", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660");
  script_osvdb_id(41989, 44057, 44906, 44907, 44908, 44909, 44910, 46584, 46638, 46639, 46641, 46690, 47796, 47797, 47798);
  script_xref(name:"GLSA", value:"200811-05");

  script_name(english:"GLSA-200811-05 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200811-05
(PHP: Multiple vulnerabilities)

    Several vulnerabilitites were found in PHP:
    PHP ships a
    vulnerable version of the PCRE library which allows for the
    circumvention of security restrictions or even for remote code
    execution in case of an application which accepts user-supplied regular
    expressions (CVE-2008-0674).
    Multiple crash issues in several
    PHP functions have been discovered.
    Ryan Permeh reported that
    the init_request_info() function in sapi/cgi/cgi_main.c does not
    properly consider operator precedence when calculating the length of
    PATH_TRANSLATED (CVE-2008-0599).
    An off-by-one error in the
    metaphone() function may lead to memory corruption.
    Maksymilian Arciemowicz of SecurityReason Research reported an
    integer overflow, which is triggerable using printf() and related
    functions (CVE-2008-1384).
    Andrei Nigmatulin reported a
    stack-based buffer overflow in the FastCGI SAPI, which has unknown
    attack vectors (CVE-2008-2050).
    Stefan Esser reported that PHP
    does not correctly handle multibyte characters inside the
    escapeshellcmd() function, which is used to sanitize user input before
    its usage in shell commands (CVE-2008-2051).
    Stefan Esser
    reported that a short-coming in PHP's algorithm of seeding the random
    number generator might allow for predictible random numbers
    (CVE-2008-2107, CVE-2008-2108).
    The IMAP extension in PHP uses
    obsolete c-client API calls making it vulnerable to buffer overflows as
    no bounds checking can be done (CVE-2008-2829).
    Tavis Ormandy
    reported a heap-based buffer overflow in pcre_compile.c in the PCRE
    version shipped by PHP when processing user-supplied regular
    expressions (CVE-2008-2371).
    CzechSec reported that specially
    crafted font files can lead to an overflow in the imageloadfont()
    function in ext/gd/gd.c, which is part of the GD extension
    (CVE-2008-3658).
    Maksymilian Arciemowicz of SecurityReason
    Research reported that a design error in PHP's stream wrappers allows
    to circumvent safe_mode checks in several filesystem-related PHP
    functions (CVE-2008-2665, CVE-2008-2666).
    Laurent Gaffie
    discovered a buffer overflow in the internal memnstr() function, which
    is used by the PHP function explode() (CVE-2008-3659).
    An
    error in the FastCGI SAPI when processing a request with multiple dots
    preceding the extension (CVE-2008-3660).
  
Impact :

    These vulnerabilities might allow a remote attacker to execute
    arbitrary code, to cause a Denial of Service, to circumvent security
    restrictions, to disclose information, and to manipulate files.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200811-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.6-r6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.2.6-r6"), vulnerable:make_list("lt 5.2.6-r6"))) flag++;

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
