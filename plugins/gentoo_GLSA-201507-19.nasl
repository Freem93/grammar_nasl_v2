#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201507-19.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(86088);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/23 14:26:24 $");

  script_cve_id("CVE-2015-0405", "CVE-2015-0423", "CVE-2015-0433", "CVE-2015-0438", "CVE-2015-0439", "CVE-2015-0441", "CVE-2015-0498", "CVE-2015-0499", "CVE-2015-0500", "CVE-2015-0501", "CVE-2015-0503", "CVE-2015-0505", "CVE-2015-0506", "CVE-2015-0507", "CVE-2015-0508", "CVE-2015-0511", "CVE-2015-2566", "CVE-2015-2567", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573");
  script_bugtraq_id(70574, 72132, 72136, 72137, 72140, 72142, 72148, 72150, 72154, 72155, 72159, 72162, 72165, 72168, 72169, 72173, 72175, 72176, 74070, 74073, 74078, 74081, 74085, 74086, 74089, 74091, 74095, 74098, 74102, 74103, 74110, 74112, 74115, 74120, 74121, 74123, 74126, 74130, 74133);
  script_xref(name:"GLSA", value:"201507-19");

  script_name(english:"GLSA-201507-19 : MySQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201507-19
(MySQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MySQL. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could send a specially crafted request, possibly
      resulting in execution of arbitrary code with the privileges of the
      application or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201507-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MySQL 5.5.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.5.43'
    All MySQL 5.6.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.6.24'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("rge 5.5.43", "ge 5.6.24"), vulnerable:make_list("lt 5.6.24"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MySQL");
}
