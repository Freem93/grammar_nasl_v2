#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14479);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0179");
  script_xref(name:"GLSA", value:"200404-14");

  script_name(english:"GLSA-200404-14 : Multiple format string vulnerabilities in cadaver");
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
"The remote host is affected by the vulnerability described in GLSA-200404-14
(Multiple format string vulnerabilities in cadaver)

    Cadaver code includes the neon library, which in versions 0.24.4 and
    previous is vulnerable to multiple format string attacks. The latest
    version of cadaver uses version 0.24.5 of the neon library, which makes it
    immune to this vulnerability.
  
Impact :

    When using cadaver to connect to an untrusted WebDAV server, this
    vulnerability can allow a malicious remote server to execute arbitrary code
    on the client with the rights of the user using cadaver.
  
Workaround :

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.webdav.org/cadaver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"cadaver users should upgrade to version 0.22.1 or later:
    # emerge sync
    # emerge -pv '>=net-misc/cadaver-0.22.1'
    # emerge '>=net-misc/cadaver-0.22.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cadaver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/cadaver", unaffected:make_list("ge 0.22.1"), vulnerable:make_list("lt 0.22.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-misc/cadaver");
}
