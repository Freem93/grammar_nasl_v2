#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200703-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24800);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0801", "CVE-2007-0981", "CVE-2007-0995");
  script_osvdb_id(30641, 32104, 32107, 32108, 32109, 32110, 32111, 32112, 32113, 32114, 32115, 79165);
  script_xref(name:"GLSA", value:"200703-08");

  script_name(english:"GLSA-200703-08 : SeaMonkey: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200703-08
(SeaMonkey: Multiple vulnerabilities)

    Tom Ferris reported a heap-based buffer overflow involving wide SVG
    stroke widths that affects SeaMonkey. Various researchers reported some
    errors in the JavaScript engine potentially leading to memory
    corruption. SeaMonkey also contains minor vulnerabilities involving
    cache collision and unsafe pop-up restrictions, filtering or CSS
    rendering under certain conditions. All those vulnerabilities are the
    same as in GLSA 200703-04 affecting Mozilla Firefox.
  
Impact :

    An attacker could entice a user to view a specially crafted web page or
    to read a specially crafted email that will trigger one of the
    vulnerabilities, possibly leading to the execution of arbitrary code.
    It is also possible for an attacker to spoof the address bar, steal
    information through cache collision, bypass the local file protection
    mechanism with pop-ups, or perform cross-site scripting attacks,
    leading to the exposure of sensitive information, such as user
    credentials.
  
Workaround :

    There is no known workaround at this time for all of these issues, but
    most of them can be avoided by disabling JavaScript. Note that the
    execution of JavaScript is disabled by default in the SeaMonkey email
    client, and enabling it is strongly discouraged."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=360493#c366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200703-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users upgrading to the following release of SeaMonkey should note that
    the corresponding Mozilla Firefox upgrade has been found to lose the
    saved passwords file in some cases. The saved passwords are encrypted
    and stored in the 'signons.txt' file of ~/.mozilla/ and we advise our
    users to save that file before performing the upgrade.
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-1.1.1'
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-1.1.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:TF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
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

if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 1.1.1"), vulnerable:make_list("lt 1.1.1"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 1.1.1"), vulnerable:make_list("lt 1.1.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SeaMonkey");
}
