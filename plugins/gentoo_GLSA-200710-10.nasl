#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200710-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(27045);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 14:04:23 $");

  script_cve_id("CVE-2007-3916");
  script_osvdb_id(40557);
  script_xref(name:"GLSA", value:"200710-10");

  script_name(english:"GLSA-200710-10 : SKK Tools: Insecure temporary file creation");
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
"The remote host is affected by the vulnerability described in GLSA-200710-10
(SKK Tools: Insecure temporary file creation)

    skkdic-expr.c insecurely writes temporary files to a location in the
    form $TMPDIR/skkdic$PID.{pag,dir,db}, where $PID is the process ID.
  
Impact :

    A local attacker could create symbolic links in the directory where the
    temporary files are written, pointing to a valid file somewhere on the
    filesystem that is writable by the user running the SKK software. When
    SKK writes the temporary file, the target valid file would then be
    overwritten with the contents of the SKK temporary file.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200710-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SKK Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-i18n/skktools-1.2-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:skktools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/15");
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

if (qpkg_check(package:"app-i18n/skktools", unaffected:make_list("ge 1.2-r1"), vulnerable:make_list("lt 1.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SKK Tools");
}
