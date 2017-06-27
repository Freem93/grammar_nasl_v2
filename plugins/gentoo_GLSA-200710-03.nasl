#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200710-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(26943);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4065", "CVE-2007-4066");
  script_osvdb_id(38675, 38676, 38677, 38678, 38679);
  script_xref(name:"GLSA", value:"200710-03");

  script_name(english:"GLSA-200710-03 : libvorbis: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200710-03
(libvorbis: Multiple vulnerabilities)

    David Thiel of iSEC Partners discovered a heap-based buffer overflow in
    the _01inverse() function in res0.c and a boundary checking error in
    the vorbis_info_clear() function in info.c (CVE-2007-3106 and
    CVE-2007-4029). libvorbis is also prone to several Denial of Service
    vulnerabilities in form of infinite loops and invalid memory access
    with unknown impact (CVE-2007-4065 and CVE-2007-4066).
  
Impact :

    A remote attacker could exploit these vulnerabilities by enticing a
    user to open a specially crafted Ogg Vorbis file or network stream with
    an application using libvorbis. This might lead to the execution of
    arbitrary code with privileges of the user playing the file or a Denial
    of Service by a crash or CPU consumption.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200710-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libvorbis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/libvorbis-1.2.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libvorbis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/libvorbis", unaffected:make_list("ge 1.2.0"), vulnerable:make_list("lt 1.2.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvorbis");
}
