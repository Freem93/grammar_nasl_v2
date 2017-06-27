#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-26.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14781);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904", "CVE-2004-0905", "CVE-2004-0906", "CVE-2004-0907", "CVE-2004-0908", "CVE-2004-0909");
  script_osvdb_id(9961, 9965, 9966, 9967, 9968, 9969, 9970, 9971, 10045, 10046);
  script_xref(name:"GLSA", value:"200409-26");

  script_name(english:"GLSA-200409-26 : Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200409-26
(Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities)

    Mozilla-based products are vulnerable to multiple security issues.
    Firstly, routines handling the display of BMP images and VCards contain
    an integer overflow and a stack buffer overrun. Specific pages with
    long links, when sent using the 'Send Page' function, and links with
    non-ASCII hostnames could both cause heap buffer overruns.
    Several issues were found and fixed in JavaScript rights handling:
    untrusted script code could read and write to the clipboard, signed
    scripts could build confusing grant privileges dialog boxes, and when
    dragged onto trusted frames or windows, JavaScript links could access
    information and rights of the target frame or window. Finally,
    Mozilla-based mail clients (Mozilla and Mozilla Thunderbird) are
    vulnerable to a heap overflow caused by invalid POP3 mail server
    responses.
  
Impact :

    An attacker might be able to run arbitrary code with the rights of the
    user running the software by enticing the user to perform one of the
    following actions: view a specially crafted BMP image or VCard, use the
    'Send Page' function on a malicious page, follow links with malicious
    hostnames, drag multiple JavaScript links in a row to another window,
    or connect to an untrusted POP3 mail server. An attacker could also use
    a malicious page with JavaScript to disclose clipboard contents or
    abuse previously-given privileges to request XPI installation
    privileges through a confusing dialog.
  
Workaround :

    There is no known workaround covering all vulnerabilities."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla1.7.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e445b231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.us-cert.gov/cas/techalerts/TA04-261A.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv your-version
    # emerge your-version"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 1.0_pre"), vulnerable:make_list("lt 1.0_pre"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 0.8"), vulnerable:make_list("lt 0.8"))) flag++;
if (qpkg_check(package:"www-client/mozilla", unaffected:make_list("ge 1.7.3"), vulnerable:make_list("lt 1.7.3"))) flag++;
if (qpkg_check(package:"www-client/epiphany", unaffected:make_list("ge 1.2.9-r1"), vulnerable:make_list("lt 1.2.9-r1"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list("ge 1.7.3"), vulnerable:make_list("lt 1.7.3"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 0.8"), vulnerable:make_list("lt 0.8"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 1.0_pre"), vulnerable:make_list("lt 1.0_pre"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla / Firefox / Thunderbird / Epiphany");
}
