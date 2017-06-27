#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200703-23.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24889);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:53 $");

  script_cve_id("CVE-2007-1049", "CVE-2007-1230", "CVE-2007-1244", "CVE-2007-1409");
  script_osvdb_id(33766, 33787, 33788, 33884, 34360, 34361);
  script_xref(name:"GLSA", value:"200703-23");

  script_name(english:"GLSA-200703-23 : WordPress: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200703-23
(WordPress: Multiple vulnerabilities)

    WordPress contains cross-site scripting or cross-site scripting forgery
    vulnerabilities reported by:
    g30rg3_x in the 'year'
    parameter of the wp_title() function
    Alexander Concha in the
    'demo' parameter of wp-admin/admin.php
    Samenspender and Stefan
    Friedli in the 'post' parameter of wp-admin/post.php and
    wp-admin/page.php, in the 'cat_ID' parameter of wp-admin/categories.php
    and in the 'c' parameter of wp-admin/comment.php
    PsychoGun in
    the 'file' parameter of wp-admin/templates.php
    Additionally, WordPress prints the full PHP script paths in some error
    messages.
  
Impact :

    The cross-site scripting vulnerabilities can be triggered to steal
    browser session data or cookies. A remote attacker can entice a user to
    browse to a specially crafted web page that can trigger the cross-site
    request forgery vulnerability and perform arbitrary WordPress actions
    with the permissions of the user. Additionally, the path disclosure
    vulnerability could help an attacker to perform other attacks.
  
Workaround :

    There is no known workaround at this time for all these
    vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/24430/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200703-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Due to the numerous recently discovered vulnerabilities in WordPress,
    this package has been masked in the portage tree. All WordPress users
    are advised to unmerge it.
    # emerge --unmerge 'www-apps/wordpress'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/wordpress", unaffected:make_list(), vulnerable:make_list("le 2.1.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WordPress");
}
