#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200608-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22171);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:56:51 $");

  script_cve_id("CVE-2006-2450");
  script_osvdb_id(27137);
  script_xref(name:"GLSA", value:"200608-12");

  script_name(english:"GLSA-200608-12 : x11vnc: Authentication bypass in included LibVNCServer code");
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
"The remote host is affected by the vulnerability described in GLSA-200608-12
(x11vnc: Authentication bypass in included LibVNCServer code)

    x11vnc includes vulnerable LibVNCServer code, which fails to properly
    validate protocol types effectively letting users decide what protocol
    to use, such as 'Type 1 - None' (GLSA-200608-05). x11vnc will accept
    this security type, even if it is not offered by the server.
  
Impact :

    An attacker could exploit this vulnerability to gain unauthorized
    access with the privileges of the user running the VNC server.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200608-05.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200608-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All x11vnc users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-misc/x11vnc-0.8.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:x11vnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-misc/x11vnc", unaffected:make_list("ge 0.8.1"), vulnerable:make_list("lt 0.8.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "x11vnc");
}
