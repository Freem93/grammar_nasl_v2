#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200712-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(29290);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:24 $");

  script_cve_id("CVE-2007-5795", "CVE-2007-6109");
  script_osvdb_id(42060, 43372);
  script_xref(name:"GLSA", value:"200712-03");

  script_name(english:"GLSA-200712-03 : GNU Emacs: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200712-03
(GNU Emacs: Multiple vulnerabilities)

    Drake Wilson reported that the hack-local-variables() function in GNU
    Emacs 22 does not properly match assignments of local variables in a
    file against a list of unsafe or risky variables, allowing to override
    them (CVE-2007-5795). Andreas Schwab (SUSE) discovered a stack-based
    buffer overflow in the format function when handling values with high
    precision (CVE-2007-6109).
  
Impact :

    Remote attackers could entice a user to open a specially crafted file
    in GNU Emacs, possibly leading to the execution of arbitrary Emacs Lisp
    code (via CVE-2007-5795) or arbitrary code (via CVE-2007-6109) with the
    privileges of the user running GNU Emacs.
  
Workaround :

    The first vulnerability can be worked around by setting the
    'enable-local-variables' option to 'nil', disabling the processing of
    local variable lists. GNU Emacs prior to version 22 is not affected by
    this vulnerability. There is no known workaround for the second
    vulnerability at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200712-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU Emacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-editors/emacs-22.1-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emacs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
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

if (qpkg_check(package:"app-editors/emacs", unaffected:make_list("ge 22.1-r3", "rge 21.4-r14", "lt 19"), vulnerable:make_list("lt 22.1-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU Emacs");
}
