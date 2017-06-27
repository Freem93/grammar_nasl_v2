#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200509-17.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19816);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-3042");
  script_osvdb_id(19575);
  script_xref(name:"GLSA", value:"200509-17");

  script_name(english:"GLSA-200509-17 : Webmin, Usermin: Remote code execution through PAM authentication");
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
"The remote host is affected by the vulnerability described in GLSA-200509-17
(Webmin, Usermin: Remote code execution through PAM authentication)

    Keigo Yamazaki discovered that the miniserv.pl webserver, used in
    both Webmin and Usermin, does not properly validate authentication
    credentials before sending them to the PAM (Pluggable Authentication
    Modules) authentication process. The default configuration shipped with
    Gentoo does not enable the 'full PAM conversations' option and is
    therefore unaffected by this flaw.
  
Impact :

    A remote attacker could bypass the authentication process and run
    any command as the root user on the target server.
  
Workaround :

    Do not enable 'full PAM conversations' in the Authentication
    options of Webmin and Usermin."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.lac.co.jp/business/sns/intelligence/SNSadvisory_e/83_e.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200509-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Webmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/webmin-1.230'
    All Usermin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/usermin-1.160'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/20");
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

if (qpkg_check(package:"app-admin/usermin", unaffected:make_list("ge 1.160"), vulnerable:make_list("lt 1.160"))) flag++;
if (qpkg_check(package:"app-admin/webmin", unaffected:make_list("ge 1.230"), vulnerable:make_list("lt 1.230"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Webmin / Usermin");
}
