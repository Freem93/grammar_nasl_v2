#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201209-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(62235);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 14:38:50 $");

  script_cve_id("CVE-2009-2347", "CVE-2009-5022", "CVE-2010-1411", "CVE-2010-2065", "CVE-2010-2067", "CVE-2010-2233", "CVE-2010-2443", "CVE-2010-2481", "CVE-2010-2482", "CVE-2010-2483", "CVE-2010-2595", "CVE-2010-2596", "CVE-2010-2597", "CVE-2010-2630", "CVE-2010-2631", "CVE-2010-3087", "CVE-2010-4665", "CVE-2011-0192", "CVE-2011-1167", "CVE-2012-1173", "CVE-2012-2088", "CVE-2012-2113", "CVE-2012-3401");
  script_osvdb_id(55821, 55822, 65296, 65676, 65754, 65795, 65968, 65969, 65970, 65971, 66082, 66083, 66084, 66089, 66090, 68274, 71256, 71257, 72233, 72260, 81025, 83042, 83628, 84090);
  script_xref(name:"GLSA", value:"201209-02");

  script_name(english:"GLSA-201209-02 : libTIFF: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201209-02
(libTIFF: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in libTIFF. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted TIFF
      file with an application making use of libTIFF, possibly resulting in
      execution of arbitrary code with the privileges of the user running the
      application or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201209-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libTIFF 4.0 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/tiff-4.0.2-r1'
    All libTIFF 3.9 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/tiff-3.9.5-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
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

if (qpkg_check(package:"media-libs/tiff", unaffected:make_list("ge 4.0.2-r1", "rge 3.9.5-r2", "rge 3.9.7-r1"), vulnerable:make_list("lt 4.0.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libTIFF");
}
