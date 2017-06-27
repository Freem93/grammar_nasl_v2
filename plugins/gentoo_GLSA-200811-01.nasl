#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200811-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(34689);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-4195", "CVE-2008-4196", "CVE-2008-4197", "CVE-2008-4198", "CVE-2008-4199", "CVE-2008-4200", "CVE-2008-4292", "CVE-2008-4694", "CVE-2008-4695", "CVE-2008-4696", "CVE-2008-4697", "CVE-2008-4698", "CVE-2008-4794", "CVE-2008-4795");
  script_osvdb_id(46697, 47688, 47689, 47690, 47691, 47692, 48719, 49093, 49094, 49472, 49473, 49739, 49740, 49741);
  script_xref(name:"GLSA", value:"200811-01");

  script_name(english:"GLSA-200811-01 : Opera: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200811-01
(Opera: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Opera:
    Opera does not restrict the ability of a framed web page to change
    the address associated with a different frame (CVE-2008-4195).
    Chris Weber (Casaba Security) discovered a Cross-site scripting
    vulnerability (CVE-2008-4196).
    Michael A. Puls II discovered
    that Opera can produce argument strings that contain uninitialized
    memory, when processing custom shortcut and menu commands
    (CVE-2008-4197).
    Lars Kleinschmidt discovered that Opera, when
    rendering an HTTP page that has loaded an HTTPS page into a frame,
    displays a padlock icon and offers a security information dialog
    reporting a secure connection (CVE-2008-4198).
    Opera does not
    prevent use of links from web pages to feed source files on the local
    disk (CVE-2008-4199).
    Opera does not ensure that the address
    field of a news feed represents the feed's actual URL
    (CVE-2008-4200).
    Opera does not check the CRL override upon
    encountering a certificate that lacks a CRL (CVE-2008-4292).
    Chris (Matasano Security) reported that Opera may crash if it is
    redirected by a malicious page to a specially crafted address
    (CVE-2008-4694).
    Nate McFeters reported that Opera runs Java
    applets in the context of the local machine, if that applet has been
    cached and a page can predict the cache path for that applet and load
    it from the cache (CVE-2008-4695).
    Roberto Suggi Liverani
    (Security-Assessment.com) reported that Opera's History Search results
    does not escape certain constructs correctly, allowing for the
    injection of scripts into the page (CVE-2008-4696).
    David
    Bloom reported that Opera's Fast Forward feature incorrectly executes
    scripts from a page held in a frame in the outermost page instead of
    the page the JavaScript URL was located (CVE-2008-4697).
    David
    Bloom reported that Opera does not block some scripts when previewing a
    news feed (CVE-2008-4698).
    Opera does not correctly sanitize
    content when certain parameters are passed to Opera's History Search,
    allowing scripts to be injected into the History Search results page
    (CVE-2008-4794).
    Opera's links panel incorrectly causes
    scripts from a page held in a frame to be executed in the outermost
    page instead of the page where the URL was located
    (CVE-2008-4795).
  
Impact :

    These vulnerabilties allow remote attackers to execute arbitrary code,
    to run scripts injected into Opera's History Search with elevated
    privileges, to inject arbitrary web script or HTML into web pages, to
    manipulate the address bar, to change Opera's preferences, to determine
    the validity of local filenames, to read cache files, browsing history,
    and subscribed feeds or to conduct other attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200811-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/opera-9.62'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Opera historysearch XSS');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 59, 79, 200, 255, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 9.62"), vulnerable:make_list("lt 9.62"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Opera");
}
