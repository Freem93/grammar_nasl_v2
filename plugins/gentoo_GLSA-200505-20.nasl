#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200505-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18384);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1520", "CVE-2005-1521", "CVE-2005-1522", "CVE-2005-1523");
  script_osvdb_id(16854, 16855, 16856, 16857);
  script_xref(name:"GLSA", value:"200505-20");

  script_name(english:"GLSA-200505-20 : Mailutils: Multiple vulnerabilities in imap4d and mail");
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
"The remote host is affected by the vulnerability described in GLSA-200505-20
(Mailutils: Multiple vulnerabilities in imap4d and mail)

    infamous41d discovered several vulnerabilities in GNU Mailutils.
    imap4d does not correctly implement formatted printing of command tags
    (CAN-2005-1523), fails to validate the range sequence of the 'FETCH'
    command (CAN-2005-1522), and contains an integer overflow in the
    'fetch_io' routine (CAN-2005-1521). mail contains a buffer overflow in
    'header_get_field_name()' (CAN-2005-1520).
  
Impact :

    A remote attacker can exploit the format string and integer
    overflow in imap4d to execute arbitrary code as the imap4d user, which
    is usually root. By sending a specially crafted email message, a remote
    attacker could exploit the buffer overflow in the 'mail' utility to
    execute arbitrary code with the rights of the user running mail.
    Finally, a remote attacker can also trigger a Denial of Service by
    sending a malicious FETCH command to an affected imap4d, causing
    excessive resource consumption.
  
Workaround :

    There are no known workarounds at this time."
  );
  # http://www.idefense.com/application/poi/display?id=249&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25ab4cb8"
  );
  # http://www.idefense.com/application/poi/display?id=248&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6033f90"
  );
  # http://www.idefense.com/application/poi/display?id=247&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ceebb2fd"
  );
  # http://www.idefense.com/application/poi/display?id=246&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7b7be14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200505-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU Mailutils users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/mailutils-0.6-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mailutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/25");
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

if (qpkg_check(package:"net-mail/mailutils", unaffected:make_list("ge 0.6-r1"), vulnerable:make_list("lt 0.6-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mailutils");
}
