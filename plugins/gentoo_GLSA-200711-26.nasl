#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-26.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(28265);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-5935", "CVE-2007-5936", "CVE-2007-5937");
  script_bugtraq_id(26469);
  script_osvdb_id(38698, 39541, 39542, 39543, 42237, 42238, 42239);
  script_xref(name:"GLSA", value:"200711-26");

  script_name(english:"GLSA-200711-26 : teTeX: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200711-26
(teTeX: Multiple vulnerabilities)

    Joachim Schrod discovered several buffer overflow vulnerabilities and
    an insecure temporary file creation in the 'dvilj' application that is
    used by dvips to convert DVI files to printer formats (CVE-2007-5937,
    CVE-2007-5936). Bastien Roucaries reported that the 'dvips' application
    is vulnerable to two stack-based buffer overflows when processing DVI
    documents with long \\href{} URIs (CVE-2007-5935). teTeX also includes
    code from Xpdf that is vulnerable to a memory corruption and two
    heap-based buffer overflows (GLSA 200711-22); and it contains code from
    T1Lib that is vulnerable to a buffer overflow when processing an overly
    long font filename (GLSA 200710-12).
  
Impact :

    A remote attacker could entice a user to process a specially crafted
    DVI or PDF file which could lead to the execution of arbitrary code
    with the privileges of the user running the application. A local
    attacker could exploit the 'dvilj' vulnerability to conduct a symlink
    attack to overwrite arbitrary files.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200710-12.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200711-22.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All teTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/tetex-3.0_p1-r6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
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

if (qpkg_check(package:"app-text/tetex", unaffected:make_list("ge 3.0_p1-r6"), vulnerable:make_list("lt 3.0_p1-r6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "teTeX");
}
