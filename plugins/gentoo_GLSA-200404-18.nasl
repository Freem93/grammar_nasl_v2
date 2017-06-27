#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-18.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14483);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0156");
  script_osvdb_id(5361);
  script_xref(name:"GLSA", value:"200404-18");

  script_name(english:"GLSA-200404-18 : Multiple Vulnerabilities in ssmtp");
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
"The remote host is affected by the vulnerability described in GLSA-200404-18
(Multiple Vulnerabilities in ssmtp)

    There are two format string vulnerabilities inside the log_event() and
    die() functions of ssmtp. Strings from outside ssmtp are passed to various
    printf()-like functions from within log_event() and die() as format
    strings. An attacker could cause a specially crafted string to be passed to
    these functions, and potentially cause ssmtp to execute arbitrary code.
  
Impact :

    If ssmtp connects to a malicious mail relay server, this vulnerability can
    be used to execute code with the rights of the mail sender, including root.
  
Workaround :

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of ssmtp."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/11378/"
  );
  # http://lists.debian.org/debian-security-announce/debian-security-announce-2004/msg00084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be198041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users are advised to upgrade to the latest available version of ssmtp.
    # emerge sync
    # emerge -pv '>=mail-mta/ssmtp-2.60.7'
    # emerge '>=mail-mta/ssmtp-2.60.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ssmtp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/15");
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

if (qpkg_check(package:"mail-mta/ssmtp", unaffected:make_list("ge 2.60.7"), vulnerable:make_list("le 2.60.4-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mail-mta/ssmtp");
}
