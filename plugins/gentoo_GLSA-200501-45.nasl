#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-45.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16436);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2005-0220");
  script_osvdb_id(13032);
  script_xref(name:"GLSA", value:"200501-45");

  script_name(english:"GLSA-200501-45 : Gallery: XSS vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200501-45
(Gallery: XSS vulnerability)

    Rafel Ivgi has discovered a cross-site scripting vulnerability where
    the 'username' parameter is not properly sanitized in 'login.php'.
  
Impact :

    By sending a carefully crafted URL, an attacker can inject and execute
    script code in the victim's browser window, and potentially compromise
    the user's gallery.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=149
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?335f9d0c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/13887/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Gallery users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/gallery-1.4.4_p6'
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gallery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/17");
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

if (qpkg_check(package:"www-apps/gallery", unaffected:make_list("ge 1.4.4_p6"), vulnerable:make_list("lt 1.4.4_p6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gallery");
}
