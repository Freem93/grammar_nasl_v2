#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201311-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70778);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/13 14:27:07 $");

  script_cve_id("CVE-2010-3443", "CVE-2013-4422");
  script_bugtraq_id(62923);
  script_osvdb_id(68209, 98285);
  script_xref(name:"GLSA", value:"201311-03");

  script_name(english:"GLSA-201311-03 : Quassel: Multiple Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201311-03
(Quassel: Multiple Vulnerabilities)

    Two vulnerabilities have been found in Quassel:
      Quassel does not properly handle multiple CTCP requests
        (CVE-2010-3443).
      Quassel, when used with certain versions of Qt and PostgreSQL, does
        not sanitize user input (CVE-2013-4422).
  
Impact :

    A remote attacker could send multiple CTCP requests in single private
      message, possibly resulting in a Denial of Service condition. Futhermore,
      a remote attacker may be able to execute arbitrary SQL statements.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201311-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Quassel users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-irc/quassel-0.9.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:quassel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-irc/quassel", unaffected:make_list("ge 0.9.1"), vulnerable:make_list("lt 0.9.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Quassel");
}
