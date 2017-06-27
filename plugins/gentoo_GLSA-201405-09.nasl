#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201405-09.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(74052);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/09 14:23:23 $");

  script_cve_id("CVE-2012-1185", "CVE-2012-1186", "CVE-2013-4298", "CVE-2014-1947", "CVE-2014-2030");
  script_bugtraq_id(51957, 62080, 65478, 65683);
  script_osvdb_id(103206);
  script_xref(name:"GLSA", value:"201405-09");

  script_name(english:"GLSA-201405-09 : ImageMagick: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201405-09
(ImageMagick: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in ImageMagick. Please
      review the CVE identifiers referenced below for details.
    Note that CVE-2012-1185 and CVE-2012-1186 were issued due to incomplete
      fixes for CVE-2012-0247 and CVE-2012-0248, respectively. The earlier CVEs
      were addressed in GLSA 201203-09.
  
Impact :

    A remote attacker can utilize multiple vectors to execute arbitrary code
      or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201405-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ImageMagick users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-gfx/imagemagick-6.8.8.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
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

if (qpkg_check(package:"media-gfx/imagemagick", unaffected:make_list("ge 6.8.8.10"), vulnerable:make_list("lt 6.8.8.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
