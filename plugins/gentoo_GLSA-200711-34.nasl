#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-34.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(28323);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_osvdb_id(35788, 36643, 37740, 37741, 37742, 37743, 37744, 37745, 38120, 38129, 38698, 39541, 39542, 39543, 42062, 42237, 42238, 42239);
  script_xref(name:"GLSA", value:"200711-34");

  script_name(english:"GLSA-200711-34 : CSTeX: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200711-34
(CSTeX: Multiple vulnerabilities)

    Multiple issues were found in the teTeX 2 codebase that CSTeX builds
    upon (GLSA 200709-17, GLSA 200711-26). CSTeX also includes vulnerable
    code from the GD library (GLSA 200708-05), from Xpdf (GLSA 200709-12,
    GLSA 200711-22) and from T1Lib (GLSA 200710-12).
  
Impact :

    Remote attackers could possibly execute arbitrary code and local
    attackers could possibly overwrite arbitrary files with the privileges
    of the user running CSTeX via multiple vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200708-05.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200709-17.xml"
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
    value:"http://www.gentoo.org/security/en/glsa/glsa-200711-26.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-34"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"CSTeX is not maintained upstream, so the package was masked in Portage.
    We recommend that users unmerge CSTeX:
    # emerge --unmerge app-text/cstetex
    As an alternative, users should upgrade their systems to use teTeX or
    TeX Live with its Babel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cstetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/cstetex", unaffected:make_list(), vulnerable:make_list("lt 2.0.2-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CSTeX");
}
