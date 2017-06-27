#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200810-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(34365);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:11:58 $");

  script_cve_id("CVE-2008-2149", "CVE-2008-3908");
  script_osvdb_id(45153, 48475, 48476, 48477, 48478, 48479);
  script_xref(name:"GLSA", value:"200810-01");

  script_name(english:"GLSA-200810-01 : WordNet: Execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200810-01
(WordNet: Execution of arbitrary code)

    Jukka Ruohonen initially reported a boundary error within the
    searchwn() function in src/wn.c. A thorough investigation by the oCERT
    team revealed several other vulnerabilities in WordNet:
    Jukka Ruohonen and Rob Holland (oCERT) reported multiple boundary
    errors within the searchwn() function in src/wn.c, the wngrep()
    function in lib/search.c, the morphstr() and morphword() functions in
    lib/morph.c, and the getindex() in lib/search.c, which lead to
    stack-based buffer overflows.
    Rob Holland (oCERT) reported two
    boundary errors within the do_init() function in lib/morph.c, which
    lead to stack-based buffer overflows via specially crafted
    'WNSEARCHDIR' or 'WNHOME' environment variables.
    Rob Holland
    (oCERT) reported multiple boundary errors in the bin_search() and
    bin_search_key() functions in binsrch.c, which lead to stack-based
    buffer overflows via specially crafted data files.
    Rob Holland
    (oCERT) reported a boundary error within the parse_index() function in
    lib/search.c, which leads to a heap-based buffer overflow via specially
    crafted data files.
  
Impact :

    In case the application is accessible e.g. via a web server,
    a remote attacker could pass overly long strings as arguments to the
    'wm' binary, possibly leading to the execution of arbitrary code.
    A local attacker could exploit the second vulnerability via
    specially crafted 'WNSEARCHDIR' or 'WNHOME' environment variables,
    possibly leading to the execution of arbitrary code with escalated
    privileges.
    A local attacker could exploit the third and
    fourth vulnerability by making the application use specially crafted
    data files, possibly leading to the execution of arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200810-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All WordNet users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-dicts/wordnet-3.0-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wordnet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-dicts/wordnet", unaffected:make_list("ge 3.0-r2"), vulnerable:make_list("lt 3.0-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WordNet");
}
