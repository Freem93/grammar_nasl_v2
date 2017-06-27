#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200607-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22080);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-3334");
  script_bugtraq_id(18698);
  script_osvdb_id(28160);
  script_xref(name:"GLSA", value:"200607-06");

  script_name(english:"GLSA-200607-06 : libpng: Buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200607-06
(libpng: Buffer overflow)

    In pngrutil.c, the function png_decompress_chunk() allocates
    insufficient space for an error message, potentially overwriting stack
    data, leading to a buffer overflow.
  
Impact :

    By enticing a user to load a maliciously crafted PNG image, an attacker
    could execute arbitrary code with the rights of the user, or crash the
    application using the libpng library, such as the
    emul-linux-x86-baselibs.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://heanet.dl.sourceforge.net/sourceforge/libpng/libpng-1.2.12-README.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ea3f267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200607-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.2.12'
    All AMD64 emul-linux-x86-baselibs users should also upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-baselibs-2.5.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-baselibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);


flag = 0;

if (qpkg_check(package:"app-emulation/emul-linux-x86-baselibs", arch:"amd64", unaffected:make_list("ge 2.5.1"), vulnerable:make_list("lt 2.5.1"))) flag++;
if (qpkg_check(package:"media-libs/libpng", unaffected:make_list("ge 1.2.12"), vulnerable:make_list("lt 1.2.12"))) flag++;

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
