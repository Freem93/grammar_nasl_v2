#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-22.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56626);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-0922", "CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231", "CVE-2009-4034", "CVE-2009-4136", "CVE-2010-0442", "CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1447", "CVE-2010-1975", "CVE-2010-3433", "CVE-2010-4015", "CVE-2011-2483");
  script_bugtraq_id(34090, 36314, 37333, 37334, 37973, 38619, 40215, 40304, 40305, 43747, 46084, 49241);
  script_osvdb_id(54512, 57901, 57917, 57918, 61038, 61039, 62129, 63208, 64755, 64756, 64757, 64792, 68436, 70740, 74742);
  script_xref(name:"GLSA", value:"201110-22");

  script_name(english:"GLSA-201110-22 : PostgreSQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-22
(PostgreSQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PostgreSQL. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote authenticated attacker could send a specially crafted SQL query
      to a PostgreSQL server with the 'intarray' module enabled, possibly
      resulting in the execution of arbitrary code with the privileges of the
      PostgreSQL server process, or a Denial of Service condition. Furthermore,
      a remote authenticated attacker could execute arbitrary Perl code, cause
      a Denial of Service condition via different vectors, bypass LDAP
      authentication, bypass X.509 certificate validation, gain database
      privileges, exploit weak blowfish encryption and possibly cause other
      unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PostgreSQL 8.2 users should upgrade to the latest 8.2 base version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-base-8.2.22:8.2'
    All PostgreSQL 8.3 users should upgrade to the latest 8.3 base version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-base-8.3.16:8.3'
    All PostgreSQL 8.4 users should upgrade to the latest 8.4 base version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-base-8.4.9:8.4'
    All PostgreSQL 9.0 users should upgrade to the latest 9.0 base version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-base-9.0.5:9.0'
    All PostgreSQL 8.2 server users should upgrade to the latest 8.2 server
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-server-8.2.22:8.2'
    All PostgreSQL 8.3 server users should upgrade to the latest 8.3 server
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-server-8.3.16:8.3'
    All PostgreSQL 8.4 server users should upgrade to the latest 8.4 server
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-server-8.4.9:8.4'
    All PostgreSQL 9.0 server users should upgrade to the latest 9.0 server
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-db/postgresql-server-9.0.5:9.0'
    The old unsplit PostgreSQL packages have been removed from portage.
      Users still using them are urged to migrate to the new PostgreSQL
      packages as stated above and to remove the old package:
      # emerge --unmerge 'dev-db/postgresql'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 264, 287, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/postgresql-server", unaffected:make_list("ge 9.0.5", "rge 8.4.9", "rge 8.3.16", "rge 8.2.22", "rge 8.4.10", "rge 8.3.17", "rge 8.2.23", "ge 8.4.11", "ge 8.3.18"), vulnerable:make_list("lt 9.0.5"))) flag++;
if (qpkg_check(package:"dev-db/postgresql-base", unaffected:make_list("ge 9.0.5", "rge 8.4.9", "rge 8.3.16", "rge 8.2.22", "rge 8.4.10", "rge 8.3.17", "rge 8.2.23", "ge 8.4.11", "ge 8.3.18"), vulnerable:make_list("lt 9.0.5"))) flag++;
if (qpkg_check(package:"dev-db/postgresql", unaffected:make_list(), vulnerable:make_list("le 9"))) flag++;

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
