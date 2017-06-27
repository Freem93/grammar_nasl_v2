#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200412-27.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16075);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_osvdb_id(12613);
  script_xref(name:"GLSA", value:"200412-27");

  script_name(english:"GLSA-200412-27 : PHProjekt: Remote code execution vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200412-27
(PHProjekt: Remote code execution vulnerability)

    cYon discovered that the authform.inc.php script allows a remote
    user to define the global variable $path_pre.
  
Impact :

    A remote attacker can exploit this vulnerability to force
    authform.inc.php to download and execute arbitrary PHP code with the
    privileges of the web server user.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.phprojekt.com/modules.php?op=modload&name=News&file=article&sid=193&mode=thread&order=0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a74c3b5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200412-27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHProjekt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/phprojekt-4.2-r2'"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phprojekt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/28");
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

if (qpkg_check(package:"www-apps/phprojekt", unaffected:make_list("ge 4.2-r2"), vulnerable:make_list("lt 4.2-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHProjekt");
}
