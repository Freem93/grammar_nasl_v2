#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201503-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(81688);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/05 13:44:21 $");

  script_cve_id("CVE-2014-3710", "CVE-2014-8142", "CVE-2014-9425", "CVE-2014-9427", "CVE-2015-0231", "CVE-2015-0232");
  script_bugtraq_id(70807, 71791, 71800, 71833, 72539, 72541);
  script_xref(name:"GLSA", value:"201503-03");

  script_name(english:"GLSA-201503-03 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201503-03
(PHP: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PHP. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A remote attacker can leverage these vulnerabilities to execute
      arbitrary code or cause Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201503-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP 5.5 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.5.21'
    All PHP 5.4 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.4.37'
    All PHP 5.3 users should upgrade to the latest version. This branch is
      currently past the end of life and it will no longer receive security
      fixes. All PHP 5.3 users are strongly recommended to upgrade to the
      current stable version of PHP 5.5 or previous stable version of PHP 5.4,
      which are supported till at least 2016 and 2015 respectively."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.5.21", "rge 5.4.37", "rge 5.4.38", "rge 5.4.39", "rge 5.4.40", "rge 5.4.41", "rge 5.4.42", "rge 5.4.43", "rge 5.4.44", "rge 5.4.45"), vulnerable:make_list("lt 5.5.21"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
