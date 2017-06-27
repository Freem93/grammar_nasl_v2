#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200505-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18271);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1409", "CVE-2005-1410");
  script_osvdb_id(16323, 16324);
  script_xref(name:"GLSA", value:"200505-12");

  script_name(english:"GLSA-200505-12 : PostgreSQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200505-12
(PostgreSQL: Multiple vulnerabilities)

    PostgreSQL gives public EXECUTE access to a number of character
    conversion routines, but doesn't validate the given arguments
    (CAN-2005-1409). It has also been reported that the contrib/tsearch2
    module of PostgreSQL misdeclares the return value of some functions as
    'internal' (CAN-2005-1410).
  
Impact :

    An attacker could call the character conversion routines with specially
    setup arguments to crash the backend process of PostgreSQL or to
    potentially gain administrator rights. A malicious user could also call
    the misdeclared functions of the contrib/tsearch2 module, resulting in
    a Denial of Service or other, yet uninvestigated, impacts.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news.315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news.315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200505-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PostgreSQL users should update to the latest available version and
    follow the guide at http://www.postgresql.o
    rg/about/news.315
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-db/postgresql"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
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

if (qpkg_check(package:"dev-db/postgresql", unaffected:make_list("eq 7.3*", "eq 7.4*", "rge 8.0.1-r3", "ge 8.0.2-r1"), vulnerable:make_list("lt 7.3.10", "lt 7.4.7-r2", "lt 8.0.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PostgreSQL");
}
