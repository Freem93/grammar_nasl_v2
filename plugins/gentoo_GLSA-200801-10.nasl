#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200801-10.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(30089);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-6526", "CVE-2007-6528", "CVE-2007-6529");
  script_osvdb_id(41175, 41176, 41177, 41178, 41179);
  script_xref(name:"GLSA", value:"200801-10");

  script_name(english:"GLSA-200801-10 : TikiWiki: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200801-10
(TikiWiki: Multiple vulnerabilities)

    Jesus Olmos Gonzalez from isecauditors reported insufficient
    sanitization of the 'movies' parameter in file tiki-listmovies.php
    (CVE-2007-6528).
    Mesut Timur from H-Labs discovered that the
    input passed to the 'area_name' parameter in file
    tiki-special_chars.php is not properly sanitised before being returned
    to the user (CVE-2007-6526).
    redflo reported multiple
    unspecified vulnerabilities in files tiki-edit_css.php,
    tiki-list_games.php, and tiki-g-admin_shared_source.php
    (CVE-2007-6529).
  
Impact :

    A remote attacker can craft the 'movies' parameter to run a directory
    traversal attack through a '..' sequence and read the first 1000 bytes
    of any arbitrary file, or conduct a cross-site scripting (XSS) attack
    through the 'area_name' parameter. This attack can be exploited to
    execute arbitrary HTML and script code in a user's browser session,
    allowing for the theft of browser session data or cookies in the
    context of the affected website. The impacts of the unspecified
    vulnerabilities are still unknown.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200801-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/tikiwiki-1.9.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tikiwiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/tikiwiki", unaffected:make_list("ge 1.9.9"), vulnerable:make_list("lt 1.9.9"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "TikiWiki");
}
