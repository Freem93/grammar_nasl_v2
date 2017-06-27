#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200701-16.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24252);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2006-5857", "CVE-2007-0044", "CVE-2007-0045", "CVE-2007-0046", "CVE-2007-0048");
  script_osvdb_id(31046, 31047, 31048, 31316, 31596);
  script_xref(name:"GLSA", value:"200701-16");

  script_name(english:"GLSA-200701-16 : Adobe Acrobat Reader: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200701-16
(Adobe Acrobat Reader: Multiple vulnerabilities)

    Adobe Acrobat Reader in stand-alone mode is vulnerable to remote code
    execution via heap corruption when loading a specially crafted PDF
    file.
    The browser plugin released with Adobe Acrobat Reader (nppdf.so) does
    not properly handle URLs, and crashes if given a URL that is too long.
    The plugin does not correctly handle JavaScript, and executes
    JavaScript that is given as a GET variable to the URL of a PDF file.
    Lastly, the plugin does not properly handle the FDF, xml, xfdf AJAX
    request parameters following the # character in a URL, allowing for
    multiple cross-site scripting vulnerabilities.
  
Impact :

    An attacker could entice a user to open a specially crafted PDF file
    and execute arbitrary code with the rights of the user running Adobe
    Acrobat Reader. An attacker could also entice a user to browse to a
    specially crafted URL and either crash the Adobe Acrobat Reader browser
    plugin, execute arbitrary JavaScript in the context of the user's
    browser, or inject arbitrary HTML or JavaScript into the document being
    viewed by the user. Note that users who have emerged Adobe Acrobat
    Reader with the 'nsplugin' USE flag disabled are not vulnerable to
    issues with the Adobe Acrobat Reader browser plugin.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200701-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Acrobat Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-7.0.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(352, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/27");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 7.0.9"), vulnerable:make_list("lt 7.0.9"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Acrobat Reader");
}
