#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14558);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0591");
  script_osvdb_id(7214);
  script_xref(name:"CERT-CC", value:"CA-2000-02");
  script_xref(name:"GLSA", value:"200408-02");

  script_name(english:"GLSA-200408-02 : Courier: XSS vulnerability in SqWebMail");
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
"The remote host is affected by the vulnerability described in GLSA-200408-02
(Courier: XSS vulnerability in SqWebMail)

    Luca Legato found that SqWebMail is vulnerable to a cross-site scripting
    (XSS) attack. An XSS attack allows an attacker to insert malicious code
    into a web-based application. SqWebMail doesn't filter appropriately data
    coming from message headers before displaying them.
  
Impact :

    By sending a carefully crafted message, an attacker can inject and execute
    script code in the victim's browser window. This allows to modify the
    behaviour of the SqWebMail application, and/or leak session information
    such as cookies to the attacker.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Courier."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Courier users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=mail-mta/courier-0.45.6.20040618'
    # emerge '>=mail-mta/courier-0.45.6.20040618'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:courier");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/21");
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

if (qpkg_check(package:"mail-mta/courier", unaffected:make_list("ge 0.45.6.20040618"), vulnerable:make_list("le 0.45.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Courier");
}
