#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201408-15.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(77459);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2013-0255", "CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901", "CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-2669");
  script_bugtraq_id(57844, 58876, 58878, 58879, 65719, 65723, 65724, 65725, 65727, 65728, 65731, 66557);
  script_osvdb_id(91960, 91962, 103544, 103545, 103546, 103547, 103548, 103549, 103551);
  script_xref(name:"GLSA", value:"201408-15");

  script_name(english:"GLSA-201408-15 : PostgreSQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201408-15
(PostgreSQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PostgreSQL. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote authenticated attacker may be able to create a Denial of
      Service condition, bypass security restrictions, or have other
      unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201408-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PostgreSQL 9.3 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-9.3.3'
    All PostgreSQL 9.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-9.2.7'
    All PostgreSQL 9.1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-9.1.12'
    All PostgreSQL 9.0 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-9.0.16'
    All PostgreSQL 8.4 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-8.4.20'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/postgresql-server", unaffected:make_list("ge 9.3.3", "rge 9.2.7", "rge 9.1.12", "rge 9.0.16", "rge 8.4.20"), vulnerable:make_list("lt 9.3.3"))) flag++;

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
