#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16394);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2004-2227", "CVE-2004-2228");
  script_osvdb_id(11118, 11591, 12637);
  script_xref(name:"GLSA", value:"200501-03");

  script_name(english:"GLSA-200501-03 : Mozilla, Firefox, Thunderbird: Various vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200501-03
(Mozilla, Firefox, Thunderbird: Various vulnerabilities)

    Maurycy Prodeus from isec.pl found a potentially exploitable buffer
    overflow in the handling of NNTP URLs. Furthermore, Martin (from
    ptraced.net) discovered that temporary files in recent versions of
    Mozilla-based products were sometimes stored world-readable with
    predictable names. The Mozilla Team also fixed a way of spoofing
    filenames in Firefox's 'What should Firefox do with this file' dialog
    boxes and a potential information leak about the existence of local
    filenames.
  
Impact :

    A remote attacker could craft a malicious NNTP link and entice a user
    to click it, potentially resulting in the execution of arbitrary code
    with the rights of the user running the browser. A local attacker could
    leverage the temporary file vulnerability to read the contents of
    another user's attachments or downloads. A remote attacker could also
    design a malicious web page that would allow to spoof filenames if the
    user uses the 'Open with...' function in Firefox, or retrieve
    information on the presence of specific files in the local filesystem.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://isec.pl/vulnerabilities/isec-0020-mozilla.txt"
  );
  # http://broadcast.ptraced.net/advisories/008-firefox.thunderbird.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29bcd626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/13144/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-1.7.5'
    All Mozilla binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-bin-1.7.5'
    All Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-1.0'
    All Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-1.0'
    All Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-0.9'
    All Thunderbird binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-bin-0.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/15");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 1.0"), vulnerable:make_list("lt 1.0"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 0.9"), vulnerable:make_list("lt 0.9"))) flag++;
if (qpkg_check(package:"www-client/mozilla", unaffected:make_list("ge 1.7.5"), vulnerable:make_list("lt 1.7.5"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list("ge 1.7.5"), vulnerable:make_list("lt 1.7.5"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 0.9"), vulnerable:make_list("lt 0.9"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 1.0"), vulnerable:make_list("lt 1.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla / Firefox / Thunderbird");
}
