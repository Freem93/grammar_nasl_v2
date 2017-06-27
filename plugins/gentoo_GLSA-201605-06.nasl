#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201605-06.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(91379);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710", "CVE-2015-2711", "CVE-2015-2712", "CVE-2015-2713", "CVE-2015-2714", "CVE-2015-2715", "CVE-2015-2716", "CVE-2015-2717", "CVE-2015-2718", "CVE-2015-2721", "CVE-2015-4000", "CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4477", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4481", "CVE-2015-4482", "CVE-2015-4483", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4490", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4493", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7575", "CVE-2016-1523", "CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1933", "CVE-2016-1935", "CVE-2016-1937", "CVE-2016-1938", "CVE-2016-1939", "CVE-2016-1940", "CVE-2016-1941", "CVE-2016-1942", "CVE-2016-1943", "CVE-2016-1944", "CVE-2016-1945", "CVE-2016-1946", "CVE-2016-1947", "CVE-2016-1948", "CVE-2016-1949", "CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967", "CVE-2016-1968", "CVE-2016-1969", "CVE-2016-1970", "CVE-2016-1971", "CVE-2016-1972", "CVE-2016-1973", "CVE-2016-1974", "CVE-2016-1975", "CVE-2016-1976", "CVE-2016-1977", "CVE-2016-1978", "CVE-2016-1979", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_xref(name:"GLSA", value:"201605-06");

  script_name(english:"GLSA-201605-06 : Mozilla Products: Multiple vulnerabilities (Logjam) (SLOTH)");
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
"The remote host is affected by the vulnerability described in GLSA-201605-06
(Mozilla Products: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Firefox, NSS, NSPR, and
      Thunderbird. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
      page or email, possibly resulting in execution of arbitrary code or a
      Denial of Service condition. Furthermore, a remote attacker may be able
      to perform Man-in-the-Middle attacks, obtain sensitive information, spoof
      the address bar, conduct clickjacking attacks, bypass security
      restrictions and protection mechanisms, or have other unspecified
      impacts.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201605-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All NSS users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/nss-3.22.2'
    All Thunderbird users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-38.7.0'
    All users of the Thunderbird binary package should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-38.7.0'
    All Firefox 38.7.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-38.7.0'
    All users of the Firefox 38.7.x binary package should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-38.7.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/nspr", unaffected:make_list("ge 4.12"), vulnerable:make_list("lt 4.12"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird-bin", unaffected:make_list("ge 38.7.0"), vulnerable:make_list("lt 38.7.0"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird", unaffected:make_list("ge 38.7.0"), vulnerable:make_list("lt 38.7.0"))) flag++;
if (qpkg_check(package:"dev-libs/nss", unaffected:make_list("ge 3.22.2"), vulnerable:make_list("lt 3.22.2"))) flag++;
if (qpkg_check(package:"www-client/firefox-bin", unaffected:make_list("ge 38.7.0"), vulnerable:make_list("lt 38.7.0"))) flag++;
if (qpkg_check(package:"www-client/firefox", unaffected:make_list("ge 38.7.0"), vulnerable:make_list("lt 38.7.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Products");
}
