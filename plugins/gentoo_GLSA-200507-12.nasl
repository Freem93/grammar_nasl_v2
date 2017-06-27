#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19199);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-2173", "CVE-2005-2174");
  script_osvdb_id(17800, 17801);
  script_xref(name:"GLSA", value:"200507-12");

  script_name(english:"GLSA-200507-12 : Bugzilla: Unauthorized access and information disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-200507-12
(Bugzilla: Unauthorized access and information disclosure)

    Bugzilla allows any user to modify the flags of any bug
    (CAN-2005-2173). Bugzilla inserts bugs into the database before marking
    them as private, in connection with MySQL replication this could lead
    to a race condition (CAN-2005-2174).
  
Impact :

    By manually changing the URL to process_bug.cgi, a remote attacker
    could modify the flags of any given bug, which could trigger an email
    including the bug summary to be sent to the attacker. The race
    condition when using Bugzilla with MySQL replication could lead to a
    short timespan (usually less than a second) where the summary of
    private bugs is exposed to all users.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.bugzilla.org/security/2.18.1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Bugzilla users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/bugzilla-2.18.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/08");
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

if (qpkg_check(package:"www-apps/bugzilla", unaffected:make_list("ge 2.18.3"), vulnerable:make_list("lt 2.18.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Bugzilla");
}
