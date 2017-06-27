#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200502-29.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17206);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0546");
  script_osvdb_id(14089, 14090, 14091, 14092, 14093);
  script_xref(name:"GLSA", value:"200502-29");

  script_name(english:"GLSA-200502-29 : Cyrus IMAP Server: Multiple overflow vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200502-29
(Cyrus IMAP Server: Multiple overflow vulnerabilities)

    Possible single byte overflows have been found in the imapd annotate
    extension and mailbox handling code. Furthermore stack-based buffer overflows
    have been found in fetchnews, the backend and imapd.
  
Impact :

    An attacker, who could be an authenticated user or an admin of a
    peering news server, could exploit these vulnerabilities to execute
    arbitrary code with the rights of the user running the Cyrus IMAP
    Server.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://asg.web.cmu.edu/archive/message.php?mailbox=archive.info-cyrus&msg=33723
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7a8533e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200502-29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Cyrus IMAP Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/cyrus-imapd-2.2.12'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/24");
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

if (qpkg_check(package:"net-mail/cyrus-imapd", unaffected:make_list("ge 2.2.12"), vulnerable:make_list("lt 2.2.12"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cyrus IMAP Server");
}
