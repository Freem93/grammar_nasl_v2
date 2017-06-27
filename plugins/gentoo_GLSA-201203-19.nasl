#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201203-19.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59611);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2011-3031", "CVE-2011-3032", "CVE-2011-3033", "CVE-2011-3034", "CVE-2011-3035", "CVE-2011-3036", "CVE-2011-3037", "CVE-2011-3038", "CVE-2011-3039", "CVE-2011-3040", "CVE-2011-3041", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044", "CVE-2011-3046", "CVE-2011-3047", "CVE-2011-3049", "CVE-2011-3050", "CVE-2011-3051", "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054", "CVE-2011-3055", "CVE-2011-3056", "CVE-2011-3057");
  script_bugtraq_id(52271, 52369, 52395, 52674);
  script_osvdb_id(79790, 79791, 79792, 79793, 79794, 79795, 79796, 79797, 79798, 79799, 79800, 79801, 79802, 79803, 79893, 80007, 80288, 80289, 80290, 80291, 80292, 80293, 80294, 80295, 80604, 89734, 92082, 92083);
  script_xref(name:"GLSA", value:"201203-19");

  script_name(english:"GLSA-201203-19 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201203-19
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium. Please review
      the CVE identifiers and release notes referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted web
      site using Chromium, possibly resulting in the execution of arbitrary
      code with the privileges of the process, a Denial of Service condition,
      Universal Cross-Site Scripting, or installation of an extension without
      user interaction.
    A remote attacker could also entice a user to install a specially
      crafted extension that would interfere with browser-issued web requests.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://googlechromereleases.blogspot.com/2012/03/chrome-stable-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e979fa5d"
  );
  # http://googlechromereleases.blogspot.com/2012/03/chrome-stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f9acfbc"
  );
  # http://googlechromereleases.blogspot.com/2012/03/chrome-stable-update_10.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfd4a569"
  );
  # http://googlechromereleases.blogspot.com/2012/03/stable-channel-update_21.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?790c7e10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201203-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-17.0.963.83'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 17.0.963.83"), vulnerable:make_list("lt 17.0.963.83"))) flag++;

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
