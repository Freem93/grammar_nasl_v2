#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-19.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14575);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0777");
  script_osvdb_id(9013);
  script_xref(name:"GLSA", value:"200408-19");

  script_name(english:"GLSA-200408-19 : courier-imap: Remote Format String Vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200408-19
(courier-imap: Remote Format String Vulnerability)

    There is a format string vulnerability in the auth_debug() function
    which can be exploited remotely, potentially leading to arbitrary code
    execution as the user running the IMAP daemon (oftentimes root). A
    remote attacker may send username or password information containing
    printf() format tokens (such as '%s'), which will crash the server or
    cause it to execute arbitrary code.
    This vulnerability can only be exploited if DEBUG_LOGIN is set to
    something other than 0 in the imapd config file.
  
Impact :

    If DEBUG_LOGIN is enabled in the imapd configuration, a remote attacker
    may execute arbitrary code as the root user.
  
Workaround :

    Set the DEBUG_LOGIN option in /etc/courier-imap/imapd to 0. (This is
    the default value.)"
  );
  # http://www.idefense.com/application/poi/display?id=131&type=vulnerabilities&flashstatus=true
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efccf26a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All courier-imap users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=net-mail/courier-imap-3.0.5'
    # emerge '>=net-mail/courier-imap-3.0.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:courier-imap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
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

if (qpkg_check(package:"net-mail/courier-imap", unaffected:make_list("ge 3.0.5"), vulnerable:make_list("le 3.0.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "courier-imap");
}
