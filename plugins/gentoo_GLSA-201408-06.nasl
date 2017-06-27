#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201408-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(77213);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/06/08 17:19:25 $");

  script_cve_id("CVE-2013-7353", "CVE-2013-7354", "CVE-2014-0333");
  script_bugtraq_id(65776, 67344, 67345);
  script_xref(name:"GLSA", value:"201408-06");

  script_name(english:"GLSA-201408-06 : libpng: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201408-06
(libpng: Multiple vulnerabilities)

    The png_push_read_chunk function in pngpread.c in the progressive
      decoder enters an infinite loop, when it encounters a zero-length IDAT
      chunk. In addition certain integer overflows have been detected and
      corrected.
    The 1.2 branch is not affected by these vulnerabilities.
  
Impact :

    A remote attacker could entice a user to open a specially crafted PNG
      file using an application linked against libpng, possibly resulting in
      Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201408-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libpng users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.6.10'
    Users with current installs in the 1.5 branch should also upgrade this
      using:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.5.18:1.5'
    Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying these packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/libpng", unaffected:make_list("ge 1.6.10", "lt 1.3", "rge 1.5.18", "rge 1.5.19", "rge 1.5.20", "rge 1.5.21", "rge 1.5.22", "rge 1.5.23", "rge 1.5.24", "rge 1.5.25"), vulnerable:make_list("lt 1.6.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng");
}
