#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201408-16.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(77460);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/09/06 13:33:34 $");

  script_cve_id("CVE-2014-0538", "CVE-2014-1700", "CVE-2014-1701", "CVE-2014-1702", "CVE-2014-1703", "CVE-2014-1704", "CVE-2014-1705", "CVE-2014-1713", "CVE-2014-1714", "CVE-2014-1715", "CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719", "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723", "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727", "CVE-2014-1728", "CVE-2014-1729", "CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1732", "CVE-2014-1733", "CVE-2014-1734", "CVE-2014-1735", "CVE-2014-1740", "CVE-2014-1741", "CVE-2014-1742", "CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746", "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3156", "CVE-2014-3157", "CVE-2014-3160", "CVE-2014-3162", "CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167", "CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3170", "CVE-2014-3171", "CVE-2014-3172", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3175", "CVE-2014-3176", "CVE-2014-3177");
  script_bugtraq_id(66120, 66239, 66243, 66249, 66252, 66704, 67082, 67374, 67375, 67376, 67517, 67572, 67972, 67977, 67980, 67981, 68677, 69192, 69201, 69202, 69203, 69398, 69400, 69401, 69402, 69403, 69405, 69406, 69407);
  script_osvdb_id(106914, 107144, 109974, 110508, 110540, 115894, 115895, 115896, 115897, 115898, 115899, 115900, 115901, 115902, 115903, 115904, 115905, 115906, 115907, 115908, 115909);
  script_xref(name:"GLSA", value:"201408-16");

  script_name(english:"GLSA-201408-16 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201408-16
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could conduct a number of attacks which include: cross
      site scripting attacks, bypassing of sandbox protection,  potential
      execution of arbitrary code with the privileges of the process, or cause
      a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201408-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-37.0.2062.94'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/30");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 37.0.2062.94"), vulnerable:make_list("lt 37.0.2062.94"))) flag++;

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
