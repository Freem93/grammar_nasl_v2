#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201606-17.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(91862);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/06/28 15:09:23 $");

  script_cve_id("CVE-2014-3686", "CVE-2015-1863", "CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143", "CVE-2015-4144", "CVE-2015-4145", "CVE-2015-4146");
  script_xref(name:"GLSA", value:"201606-17");

  script_name(english:"GLSA-201606-17 : hostapd and wpa_supplicant: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201606-17
(hostapd and wpa_supplicant: Multiple vulnerabilities)

    Multiple vulnerabilities exist in both hostapd and wpa_supplicant.
      Please review the CVE identifiers for more information.
  
Impact :

    Remote attackers could execute arbitrary code with the privileges of the
      process or cause Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201606-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All hostapd users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-wireless/hostapd-2.5'
    All wpa_supplicant users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=net-wireless/wpa_supplicant-2.5-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-wireless/wpa_supplicant", unaffected:make_list("ge 2.5-r1"), vulnerable:make_list("lt 2.5-r1"))) flag++;
if (qpkg_check(package:"net-wireless/hostapd", unaffected:make_list("ge 2.5"), vulnerable:make_list("lt 2.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hostapd and wpa_supplicant");
}
