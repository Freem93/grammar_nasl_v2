#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201010-01.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(49771);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/13 14:56:00 $");

  script_cve_id("CVE-2010-0205", "CVE-2010-1205", "CVE-2010-2249");
  script_bugtraq_id(38478, 41174);
  script_osvdb_id(62670, 65852, 65853, 66600);
  script_xref(name:"GLSA", value:"201010-01");

  script_name(english:"GLSA-201010-01 : Libpng: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201010-01
(Libpng: Multiple vulnerabilities)

    Multiple vulnerabilities were found in libpng:
      The png_decompress_chunk() function in pngrutil.c does not properly
        handle certain type of compressed data (CVE-2010-0205)
      A buffer overflow in pngread.c when using progressive applications
        (CVE-2010-1205)
      A memory leak in pngrutil.c when dealing with a certain type of
        chunks (CVE-2010-2249)
  
Impact :

    An attacker could exploit these vulnerabilities to cause programs linked
      against the library to crash or execute arbitrary code with the
      permissions of the user running the vulnerable program, which could be
      the root user.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201010-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libpng 1.4 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.4.3'
    All libpng 1.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.2.46'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/libpng", unaffected:make_list("ge 1.4.3", "ge 1.2.46"), vulnerable:make_list("lt 1.4.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Libpng");
}
