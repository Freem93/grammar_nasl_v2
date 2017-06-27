#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200911-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(42913);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-5005", "CVE-2008-5006", "CVE-2008-5514");
  script_bugtraq_id(32958);
  script_osvdb_id(49484, 49485, 49793, 52905);
  script_xref(name:"GLSA", value:"200911-03");

  script_name(english:"GLSA-200911-03 : UW IMAP toolkit: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200911-03
(UW IMAP toolkit: Multiple vulnerabilities)

    Multiple vulnerabilities were found in the UW IMAP toolkit:
    Aron Andersson and Jan Sahlin of Bitsec reported boundary errors in
    the 'tmail' and 'dmail' utilities when processing overly long mailbox
    names, leading to stack-based buffer overflows (CVE-2008-5005).
    An error in smtp.c in the c-client library was found, leading to a
    NULL pointer dereference vulnerability (CVE-2008-5006).
    Ludwig
    Nussel reported an off-by-one error in the rfc822_output_char()
    function in the RFC822BUFFER routines in the c-client library, as used
    by the UW IMAP toolkit (CVE-2008-5514).
  
Impact :

    A remote attacker could send an e-mail to a destination mailbox name
    composed of a username and '+' character followed by a long string,
    possibly leading to the execution of arbitrary code. A local attacker
    could gain privileges by specifying a long folder extension argument to
    the tmail or dmail program. Furthermore, a remote attacker could send a
    specially crafted mail message to the UW IMAP toolkit or another daemon
    using the c-client library, leading to a Denial of Service. A remote
    SMTP server could respond to the QUIT command with a close of the TCP
    connection instead of the expected 221 response code, possibly leading
    to a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200911-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All c-client library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/c-client-2007e'
    All UW IMAP toolkit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/uw-imap-2007e'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:c-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:uw-imap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-libs/c-client", unaffected:make_list("ge 2007e"), vulnerable:make_list("lt 2007e"))) flag++;
if (qpkg_check(package:"net-mail/uw-imap", unaffected:make_list("ge 2007e"), vulnerable:make_list("lt 2007e"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "UW IMAP toolkit");
}
