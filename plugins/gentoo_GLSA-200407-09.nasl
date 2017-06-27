#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-09.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14542);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0708");
  script_osvdb_id(6704);
  script_xref(name:"GLSA", value:"200407-09");

  script_name(english:"GLSA-200407-09 : MoinMoin: Group ACL bypass");
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
"The remote host is affected by the vulnerability described in GLSA-200407-09
(MoinMoin: Group ACL bypass)

    MoinMoin contains a bug in the code handling administrative group ACLs.
    A user created with the same name as an administrative group gains the
    privileges of the administrative group.
  
Impact :

    If an administrative group called AdminGroup existed an attacker could
    create a user called AdminGroup and gain the privileges of the group
    AdminGroup. This could lead to unauthorized users gaining
    administrative access.
  
Workaround :

    For every administrative group with special privileges create a user
    with the same name as the group."
  );
  # http://sourceforge.net/tracker/index.php?func=detail&aid=948103&group_id=8482&atid=108482
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7f29b25"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest available version of MoinMoin,
    as follows:
    # emerge sync
    # emerge -pv '>=www-apps/moinmoin-1.2.2'
    # emerge '>=www-apps/moinmoin-1.2.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:moinmoin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/04");
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

if (qpkg_check(package:"www-apps/moinmoin", unaffected:make_list("ge 1.2.2"), vulnerable:make_list("le 1.2.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MoinMoin");
}
