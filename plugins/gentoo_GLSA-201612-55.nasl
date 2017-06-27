#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201612-55.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(96230);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/03 14:55:09 $");

  script_xref(name:"GLSA", value:"201612-55");

  script_name(english:"GLSA-201612-55 : libjpeg-turbo: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-201612-55
(libjpeg-turbo: User-assisted execution of arbitrary code)

    The accelerated Huffman decoder was previously invoked if there were 128
      bytes in the input buffer. However, it is possible to construct a JPEG
      image with Huffman blocks > 430 bytes in length. This release simply
      increases the minimum buffer size for the accelerated Huffman decoder to
      512 bytes, which should accommodate any possible input.
  
Impact :

    A remote attacker could coerce the victim to run a specially crafted
      image file resulting in the execution of arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.mozilla.org/images/7/77/Libjpeg-turbo-report.pdf"
  );
  # https://github.com/libjpeg-turbo/libjpeg-turbo/commit/0463f7c9aad060fcd56e98d025ce16185279e2bc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66e8f916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201612-55"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libjpeg-turbo users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libjpeg-turbo-1.5.0'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libjpeg-turbo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/libjpeg-turbo", unaffected:make_list("ge 1.5.0"), vulnerable:make_list("lt 1.5.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjpeg-turbo");
}
