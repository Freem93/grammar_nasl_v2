#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201009-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(49098);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/13 14:19:43 $");

  script_cve_id("CVE-2009-2369");
  script_osvdb_id(55520);
  script_xref(name:"GLSA", value:"201009-01");

  script_name(english:"GLSA-201009-01 : wxGTK: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-201009-01
(wxGTK: User-assisted execution of arbitrary code)

    wxGTK is prone to an integer overflow error in the wxImage::Create()
    function in src/common/image.cpp, possibly leading to a heap-based
    buffer overflow.
  
Impact :

    A remote attacker might entice a user to open a specially crafted JPEG
    file using a program that uses wxGTK, possibly resulting in the remote
    execution of arbitrary code with the privileges of the user running the
    application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201009-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All wxGTK 2.6 users should upgrade to an updated version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/wxGTK-2.6.4.0-r5'
    All wxGTK 2.8 users should upgrade to an updated version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/wxGTK-2.8.10.1-r1'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
    available since August 9, 2009. It is likely that your system is
    already no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wxGTK");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-libs/wxGTK", unaffected:make_list("rge 2.6.4.0-r5", "ge 2.8.10.1-r1"), vulnerable:make_list("lt 2.8.10.1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wxGTK");
}
