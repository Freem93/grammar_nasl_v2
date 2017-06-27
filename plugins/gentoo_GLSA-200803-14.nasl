#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31440);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_cve_id("CVE-2008-0411");
  script_bugtraq_id(28017);
  script_osvdb_id(42310);
  script_xref(name:"GLSA", value:"200803-14");

  script_name(english:"GLSA-200803-14 : Ghostscript: Buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200803-14
(Ghostscript: Buffer overflow)

    Chris Evans (Google Security) discovered a stack-based buffer overflow
    within the zseticcspace() function in the file zicc.c when processing a
    PostScript file containing a long 'Range' array in a .seticcscpate
    operator.
  
Impact :

    A remote attacker could exploit this vulnerability by enticing a user
    to open a specially crafted PostScript file, which could possibly lead
    to the execution of arbitrary code or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ghostscript ESP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/ghostscript-esp-8.15.4-r1'
    All Ghostscript GPL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/ghostscript-gpl-8.61-r3'
    All Ghostscript GNU users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/ghostscript-gnu-8.60.0-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ghostscript-esp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ghostscript-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ghostscript-gpl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
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

if (qpkg_check(package:"app-text/ghostscript-esp", unaffected:make_list("ge 8.15.4-r1"), vulnerable:make_list("lt 8.15.4-r1"))) flag++;
if (qpkg_check(package:"app-text/ghostscript-gpl", unaffected:make_list("ge 8.61-r3"), vulnerable:make_list("lt 8.61-r3"))) flag++;
if (qpkg_check(package:"app-text/ghostscript-gnu", unaffected:make_list("ge 8.60.0-r2"), vulnerable:make_list("lt 8.60.0-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ghostscript");
}
