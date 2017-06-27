#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-15.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59668);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/13 14:56:00 $");

  script_cve_id("CVE-2009-5063", "CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692", "CVE-2011-3026", "CVE-2011-3045", "CVE-2011-3048", "CVE-2011-3464");
  script_bugtraq_id(48474, 48618, 48660, 51823, 52049, 52453, 52830);
  script_osvdb_id(73493, 73982, 73983, 73984, 74757, 78752, 79294, 80232, 80822);
  script_xref(name:"GLSA", value:"201206-15");

  script_name(english:"GLSA-201206-15 : libpng: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-15
(libpng: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in libpng:
      The &ldquo;embedded_profile_len()&rdquo; function in pngwutil.c does not
        check for negative values, resulting in a memory leak (CVE-2009-5063).
      The &ldquo;png_format_buffer()&rdquo; function in pngerror.c contains an
        off-by-one error (CVE-2011-2501).
      The &ldquo;png_rgb_to_gray()&rdquo; function in pngrtran.c contains an
        integer overflow error (CVE-2011-2690).
      The &ldquo;png_err()&rdquo; function in pngerror.c contains a NULL pointer
        dereference error (CVE-2011-2691).
      The &ldquo;png_handle_sCAL()&rdquo; function in pngrutil.c improperly handles
        malformed sCAL chunks(CVE-2011-2692).
      The &ldquo;png_decompress_chunk()&rdquo; function in pngrutil.c contains an
        integer overflow error (CVE-2011-3026).
      The &ldquo;png_inflate()&rdquo; function in pngrutil.c contains and out of
        bounds error (CVE-2011-3045).
      The &ldquo;png_set_text_2()&rdquo; function in pngset.c contains an error
        which could result in memory corruption (CVE-2011-3048).
      The &ldquo;png_formatted_warning()&rdquo; function in pngerror.c contains an
        off-by-one error (CVE-2011-3464).
  
Impact :

    An attacker could exploit these vulnerabilities to execute arbitrary
      code with the permissions of the user running the vulnerable program,
      which could be the root user, or to cause programs linked against the
      library to crash.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libpng 1.5 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.5.10'
    All libpng 1.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.2.49'
    Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying some of these packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/libpng", unaffected:make_list("ge 1.5.10", "ge 1.2.49"), vulnerable:make_list("lt 1.5.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng");
}
