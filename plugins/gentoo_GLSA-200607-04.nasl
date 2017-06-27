#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200607-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22011);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_osvdb_id(25730, 25731);
  script_xref(name:"GLSA", value:"200607-04");

  script_name(english:"GLSA-200607-04 : PostgreSQL: SQL injection");
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
"The remote host is affected by the vulnerability described in GLSA-200607-04
(PostgreSQL: SQL injection)

    PostgreSQL contains a flaw in the string parsing routines that allows
    certain backslash-escaped characters to be bypassed with some multibyte
    character encodings. This vulnerability was discovered by Akio Ishida
    and Yasuo Ohgaki.
  
Impact :

    An attacker could execute arbitrary SQL statements on the PostgreSQL
    server. Be aware that web applications using PostgreSQL as a database
    back-end might be used to exploit this vulnerability.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/techdocs.50"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200607-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PostgreSQL users should upgrade to the latest version in the
    respective branch they are using:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-db/postgresql
    Note: While a fix exists for the 7.3 branch it doesn't currently work
    on Gentoo. All 7.3.x users of PostgreSQL should consider updating their
    installations to the 7.4 (or higher) branch as soon as possible!"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/postgresql", unaffected:make_list("ge 8.0.8", "eq 7.4*"), vulnerable:make_list("lt 8.0.8", "lt 7.4.13"))) flag++;

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
