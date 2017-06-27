#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200902-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35732);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 14:11:59 $");

  script_cve_id("CVE-2008-2142", "CVE-2008-3949");
  script_bugtraq_id(29176);
  script_osvdb_id(45088, 49558);
  script_xref(name:"GLSA", value:"200902-06");

  script_name(english:"GLSA-200902-06 : GNU Emacs, XEmacs: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200902-06
(GNU Emacs, XEmacs: Multiple vulnerabilities)

    Morten Welinder reports about GNU Emacs and edit-utils in XEmacs: By
    shipping a .flc accompanying a source file (.c for example) and setting
    font-lock-support-mode to fast-lock-mode in the source file through
    local variables, any Lisp code in the .flc file is executed without
    warning (CVE-2008-2142).
    Romain Francoise reported a security risk in a feature of GNU Emacs
    related to interacting with Python. The vulnerability arises because
    Python, by default, prepends the current directory to the module search
    path, allowing for arbitrary code execution when launched from a
    specially crafted directory (CVE-2008-3949).
  
Impact :

    Remote attackers could entice a user to open a specially crafted file
    in GNU Emacs, possibly leading to the execution of arbitrary Emacs Lisp
    code or arbitrary Python code with the privileges of the user running
    GNU Emacs or XEmacs.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200902-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU Emacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-editors/emacs-22.2-r3'
    All edit-utils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-xemacs/edit-utils-2.39'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:edit-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emacs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-editors/emacs", unaffected:make_list("ge 22.2-r3", "rge 21.4-r17", "lt 19"), vulnerable:make_list("lt 22.2-r3"))) flag++;
if (qpkg_check(package:"app-xemacs/edit-utils", unaffected:make_list("ge 2.39"), vulnerable:make_list("lt 2.39"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU Emacs / XEmacs");
}
