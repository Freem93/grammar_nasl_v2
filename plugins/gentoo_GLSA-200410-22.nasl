#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200410-22.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15558);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");
  script_osvdb_id(10658, 10659, 10660, 10959, 10985);
  script_xref(name:"GLSA", value:"200410-22");

  script_name(english:"GLSA-200410-22 : MySQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200410-22
(MySQL: Multiple vulnerabilities)

    The following vulnerabilities were found and fixed in MySQL:
    Oleksandr Byelkin found that ALTER TABLE ... RENAME checks CREATE/INSERT
    rights of the old table instead of the new one (CAN-2004-0835). Another
    privilege checking bug allowed users to grant rights on a database they had
    no rights on.
    Dean Ellis found a defect where multiple threads ALTERing the MERGE tables
    to change the UNION could cause the server to crash (CAN-2004-0837).
    Another crash was found in MATCH ... AGAINST() queries with missing closing
    double quote.
    Finally, a buffer overrun in the mysql_real_connect function was found by
    Lukasz Wojtow (CAN-2004-0836).
  
Impact :

    The privilege checking issues could be used by remote users to bypass their
    rights on databases. The two crashes issues could be exploited by a remote
    user to perform a Denial of Service attack on MySQL server. The buffer
    overrun issue could also be exploited as a Denial of Service attack, and
    may allow to execute arbitrary code with the rights of the MySQL daemon
    (typically, the 'mysql' user).
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.mysql.com/bug.php?id=3933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.mysql.com/bug.php?id=3870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200410-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MySQL users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=dev-db/mysql-4.0.21'
    # emerge '>=dev-db/mysql-4.0.21'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/29");
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

if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 4.0.21"), vulnerable:make_list("lt 4.0.21"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MySQL");
}
