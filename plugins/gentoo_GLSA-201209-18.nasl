#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201209-18.
#
# The advisory text is Copyright (C) 2001-2014 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/2.5/
#

include("compat.inc");

if (description)
{
  script_id(62360);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/03/07 21:45:18 $");

  script_cve_id("CVE-2012-0811", "CVE-2012-0812");
  script_bugtraq_id(51680);
  script_osvdb_id(78559, 78560, 78561, 78562, 78563, 78564, 78565, 78566, 78567);
  script_xref(name:"GLSA", value:"201209-18");

  script_name(english:"GLSA-201209-18 : Postfixadmin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201209-18
(Postfixadmin: Multiple vulnerabilities)

    Multiple SQL injection vulnerabilities (CVE-2012-0811) and cross-site
      scripting vulnerabilities (CVE-2012-0812) have been found in
      Postfixadmin.
  
Impact :

    A remote attacker could exploit these vulnerabilities to execute
      arbitrary SQL statements or arbitrary HTML and script code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-201209-18.xml"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Postfixadmin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/postfixadmin-2.3.5'"
  );

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postfixadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/postfixadmin", unaffected:make_list("ge 2.3.5"), vulnerable:make_list("lt 2.3.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Postfixadmin");
}
