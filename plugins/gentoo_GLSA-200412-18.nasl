#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200412-18.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16005);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_osvdb_id(12431);
  script_xref(name:"GLSA", value:"200412-18");

  script_name(english:"GLSA-200412-18 : abcm2ps: Buffer overflow vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200412-18
(abcm2ps: Buffer overflow vulnerability)

    Limin Wang has located a buffer overflow inside the put_words()
    function in the abcm2ps code.
  
Impact :

    A remote attacker could convince the victim to download a
    specially crafted ABC file. Upon execution, this file would trigger the
    buffer overflow and lead to the execution of arbitrary code with the
    permissions of the user running abcm2ps.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://moinejf.free.fr/abcm2ps-3.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d2d126c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/13523/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200412-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All abcm2ps users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-sound/abcm2ps-3.7.21'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:abcm2ps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-sound/abcm2ps", unaffected:make_list("ge 3.7.21"), vulnerable:make_list("lt 3.7.21"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abcm2ps");
}
