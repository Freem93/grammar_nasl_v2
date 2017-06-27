#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200403-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14457);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0224");
  script_bugtraq_id(9845);
  script_xref(name:"GLSA", value:"200403-06");

  script_name(english:"GLSA-200403-06 : Multiple remote buffer overflow vulnerabilities in Courier");
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
"The remote host is affected by the vulnerability described in GLSA-200403-06
(Multiple remote buffer overflow vulnerabilities in Courier)

    The vulnerabilities have been found in the 'SHIFT_JIS' converter in
    'shiftjis.c' and 'ISO2022JP' converter in 'so2022jp.c'. An attacker may
    supply Unicode characters that exceed BMP (Basic Multilingual Plane) range,
    causing an overflow.
  
Impact :

    An attacker without privileges may exploit this vulnerability remotely, allowing arbitrary code to be executed in order to gain unauthorized access.
  
Workaround :

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200403-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to current versions of the affected packages:
    # emerge sync
    # emerge -pv '>=net-mail/courier-imap-3.0.0'
    # emerge '>=net-mail/courier-imap-3.0.0'
    # ** Or; depending on your installation... **
    # emerge -pv '>=mail-mta/courier-0.45'
    # emerge '>=mail-mta/courier-0.45'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:courier-imap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/26");
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

if (qpkg_check(package:"mail-mta/courier", unaffected:make_list("ge 0.45"), vulnerable:make_list("lt 0.45"))) flag++;
if (qpkg_check(package:"net-mail/courier-imap", unaffected:make_list("ge 3.0.0"), vulnerable:make_list("lt 3.0.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mail-mta/courier / net-mail/courier-imap");
}
