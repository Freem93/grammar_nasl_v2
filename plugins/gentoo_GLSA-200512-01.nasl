#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200512-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20280);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3962");
  script_osvdb_id(21345, 22255);
  script_xref(name:"GLSA", value:"200512-01");

  script_name(english:"GLSA-200512-01 : Perl: Format string errors can lead to code execution");
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
"The remote host is affected by the vulnerability described in GLSA-200512-01
(Perl: Format string errors can lead to code execution)

    Jack Louis discovered a new way to exploit format string errors in
    Perl that could lead to the execution of arbitrary code. This is
    perfomed by causing an integer wrap overflow in the efix variable
    inside the function Perl_sv_vcatpvfn. The proposed fix closes that
    specific exploitation vector to mitigate the risk of format string
    programming errors in Perl. This fix does not remove the need to fix
    such errors in Perl code.
  
Impact :

    Perl applications making improper use of printf functions (or
    derived functions) using untrusted data may be vulnerable to the
    already-known forms of Perl format string exploits and also to the
    execution of arbitrary code.
  
Workaround :

    Fix all misbehaving Perl applications so that they make proper use
    of the printf and derived Perl functions."
  );
  # http://www.dyadsecurity.com/perl-0002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a844180b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/418460/30/30"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200512-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/01");
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

if (qpkg_check(package:"dev-lang/perl", unaffected:make_list("ge 5.8.7-r3", "rge 5.8.6-r8"), vulnerable:make_list("lt 5.8.7-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Perl");
}
