#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200506-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18465);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1751", "CVE-2005-1759");
  script_osvdb_id(16848, 17289);
  script_xref(name:"GLSA", value:"200506-08");

  script_name(english:"GLSA-200506-08 : GNU shtool, ocaml-mysql: Insecure temporary file creation");
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
"The remote host is affected by the vulnerability described in GLSA-200506-08
(GNU shtool, ocaml-mysql: Insecure temporary file creation)

    Eric Romang has discovered that GNU shtool insecurely creates
    temporary files with predictable filenames (CAN-2005-1751). On closer
    inspection, Gentoo Security discovered that the shtool temporary file,
    once created, was being reused insecurely (CAN-2005-1759).
  
Impact :

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When a GNU shtool script is executed, this would result in the file
    being overwritten with the rights of the user running the script, which
    could be the root user.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200506-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU shtool users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-util/shtool-2.0.1-r2'
    All ocaml-mysql users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-ml/ocaml-mysql-1.0.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ocaml-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:shtool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-util/shtool", unaffected:make_list("ge 2.0.1-r2"), vulnerable:make_list("lt 2.0.1-r2"))) flag++;
if (qpkg_check(package:"dev-ml/ocaml-mysql", unaffected:make_list("ge 1.0.3-r1"), vulnerable:make_list("lt 1.0.3-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU shtool / ocaml-mysql");
}
