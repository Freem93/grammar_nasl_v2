#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200901-13.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35432);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-2927", "CVE-2008-2955", "CVE-2008-2957", "CVE-2008-3532");
  script_osvdb_id(46576, 46838, 47008, 47583, 48330);
  script_xref(name:"GLSA", value:"200901-13");

  script_name(english:"GLSA-200901-13 : Pidgin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200901-13
(Pidgin: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Pidgin and the
    libpurple library:
    A participant to the TippingPoint ZDI reported multiple integer
    overflows in the msn_slplink_process_msg() function in the MSN protocol
    implementation (CVE-2008-2927).
    Juan Pablo Lopez Yacubian is credited for reporting a use-after-free
    flaw in msn_slplink_process_msg() in the MSN protocol implementation
    (CVE-2008-2955).
    The included UPnP server does not limit the size of data to be
    downloaded for UPnP service discovery, according to a report by Andrew
    Hunt and Christian Grothoff (CVE-2008-2957).
    Josh Triplett discovered that the NSS plugin for libpurple does not
    properly verify SSL certificates (CVE-2008-3532).
  
Impact :

    A remote attacker could send specially crafted messages or files using
    the MSN protocol which could result in the execution of arbitrary code
    or crash Pidgin. NOTE: Successful exploitation might require the
    victim's interaction. Furthermore, an attacker could conduct
    man-in-the-middle attacks to obtain sensitive information using bad
    certificates and cause memory and disk resources to exhaust.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200901-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Pidgin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/pidgin-2.5.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-im/pidgin", unaffected:make_list("ge 2.5.1"), vulnerable:make_list("lt 2.5.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Pidgin");
}
