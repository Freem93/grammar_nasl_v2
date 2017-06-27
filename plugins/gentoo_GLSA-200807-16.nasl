#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200807-16.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33782);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");
  script_osvdb_id(47478, 47479, 47480, 47481, 50092, 50093, 50094, 50095, 50096);
  script_xref(name:"GLSA", value:"200807-16");

  script_name(english:"GLSA-200807-16 : Python: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200807-16
(Python: Multiple vulnerabilities)

    Multiple vulnerabilities were discovered in Python:
    David Remahl of Apple Product Security reported several integer
    overflows in core modules such as stringobject, unicodeobject,
    bufferobject, longobject, tupleobject, stropmodule, gcmodule,
    mmapmodule (CVE-2008-2315).
    David Remahl of Apple Product Security also reported an integer
    overflow in the hashlib module, leading to unreliable cryptographic
    digest results (CVE-2008-2316).
    Justin Ferguson reported multiple buffer overflows in unicode string
    processing that only affect 32bit systems (CVE-2008-3142).
    The Google Security Team reported multiple integer overflows
    (CVE-2008-3143).
    Justin Ferguson reported multiple integer underflows and overflows in
    the PyOS_vsnprintf() function, and an off-by-one error when passing
    zero-length strings, leading to memory corruption (CVE-2008-3144).
  
Impact :

    A remote attacker could exploit these vulnerabilities in Python
    applications or daemons that pass user-controlled input to vulnerable
    functions. Exploitation might lead to the execution of arbitrary code
    or a Denial of Service. Vulnerabilities within the hashlib might lead
    to weakened cryptographic protection of data integrity or authenticity.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200807-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Python 2.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/python-2.4.4-r14'
    All Python 2.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/python-2.5.2-r6'
    Please note that Python 2.3 is masked since June 24, and we will not be
    releasing updates to it. It will be removed from the tree in the near
    future."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/01");
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

if (qpkg_check(package:"dev-lang/python", unaffected:make_list("rge 2.4.4-r14", "ge 2.5.2-r6", "rge 2.4.6"), vulnerable:make_list("lt 2.5.2-r6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Python");
}
