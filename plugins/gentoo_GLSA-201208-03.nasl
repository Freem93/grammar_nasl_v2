#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201208-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(61542);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/13 14:19:45 $");

  script_cve_id("CVE-2012-2815", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2823", "CVE-2012-2824", "CVE-2012-2825", "CVE-2012-2826", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2834", "CVE-2012-2842", "CVE-2012-2843", "CVE-2012-2846", "CVE-2012-2847", "CVE-2012-2848", "CVE-2012-2849", "CVE-2012-2853", "CVE-2012-2854", "CVE-2012-2857", "CVE-2012-2858", "CVE-2012-2859", "CVE-2012-2860");
  script_bugtraq_id(54203, 54386, 54749);
  script_osvdb_id(83238, 83241, 83242, 83243, 83244, 83245, 83246, 83247, 83250, 83252, 83254, 83255, 83256, 83257, 83727, 83734, 84366, 84367, 84368, 84369, 84373, 84374, 84377, 84378, 84379, 84380);
  script_xref(name:"GLSA", value:"201208-03");

  script_name(english:"GLSA-201208-03 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201208-03
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium. Please review
      the CVE identifiers and release notes referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted web
      site using Chromium, possibly resulting in the execution of arbitrary
      code with the privileges of the process, a Denial of Service condition,
      disclosure of sensitive information, or other unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://googlechromereleases.blogspot.com/2012/06/stable-channel-update_26.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9fd4072"
  );
  # http://googlechromereleases.blogspot.com/2012/07/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22b7bf02"
  );
  # http://googlechromereleases.blogspot.com/2012/07/stable-channel-release.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9ad90b3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201208-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-21.0.1180.57'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 21.0.1180.57"), vulnerable:make_list("lt 21.0.1180.57"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
