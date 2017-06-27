#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200511-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20157);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-3393", "CVE-2005-3409");
  script_osvdb_id(20415, 20416);
  script_xref(name:"GLSA", value:"200511-07");

  script_name(english:"GLSA-200511-07 : OpenVPN: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200511-07
(OpenVPN: Multiple vulnerabilities)

    The OpenVPN client contains a format string bug in the handling of
    the foreign_option in options.c. Furthermore, when the OpenVPN server
    runs in TCP mode, it may dereference a NULL pointer under specific
    error conditions.
  
Impact :

    A remote attacker could setup a malicious OpenVPN server and trick
    the user into connecting to it, potentially executing arbitrary code on
    the client's computer. A remote attacker could also exploit the NULL
    dereference issue by sending specific packets to an OpenVPN server
    running in TCP mode, resulting in a Denial of Service condition.
  
Workaround :

    Do not use 'pull' or 'client' options in the OpenVPN client
    configuration file, and use UDP mode for the OpenVPN server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openvpn.net/changelog.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200511-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenVPN users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/openvpn-2.0.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/openvpn", unaffected:make_list("ge 2.0.4"), vulnerable:make_list("lt 2.0.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenVPN");
}
