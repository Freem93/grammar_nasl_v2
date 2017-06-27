#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200607-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22012);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-3007", "CVE-2006-3534", "CVE-2006-3535");
  script_osvdb_id(26286, 30081, 30082);
  script_xref(name:"GLSA", value:"200607-05");

  script_name(english:"GLSA-200607-05 : SHOUTcast server: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200607-05
(SHOUTcast server: Multiple vulnerabilities)

    The SHOUTcast server is vulnerable to a file disclosure when the server
    receives a specially crafted GET request. Furthermore it also fails to
    sanitize the input passed to the 'Description', 'URL', 'Genre', 'AIM',
    and 'ICQ' fields.
  
Impact :

    By sending a specially crafted GET request to the SHOUTcast server, the
    attacker can read any file that can be read by the SHOUTcast process.
    Furthermore it is possible that various request variables could also be
    exploited to execute arbitrary scripts in the context of a victim's
    browser.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://people.ksp.sk/~goober/advisory/001-shoutcast.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/20524/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200607-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SHOUTcast server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-sound/shoutcast-server-bin-1.9.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:shoutcast-server-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/08");
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

if (qpkg_check(package:"media-sound/shoutcast-server-bin", unaffected:make_list("ge 1.9.7"), vulnerable:make_list("lt 1.9.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SHOUTcast server");
}
