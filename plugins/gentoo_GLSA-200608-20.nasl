#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200608-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22242);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:51 $");

  script_cve_id("CVE-2006-4111", "CVE-2006-4112");
  script_osvdb_id(27822, 28428);
  script_xref(name:"GLSA", value:"200608-20");

  script_name(english:"GLSA-200608-20 : Ruby on Rails: Several vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200608-20
(Ruby on Rails: Several vulnerabilities)

    The Ruby on Rails developers have corrected some weaknesses in
    action_controller/, relative to the handling of the user input and the
    LOAD_PATH variable. A remote attacker could inject arbitrary entries
    into the LOAD_PATH variable and alter the main Ruby on Rails process.
    The security hole has only been partly solved in version 1.1.5. Version
    1.1.6 now fully corrects it.
  
Impact :

    A remote attacker that would exploit these weaknesses might cause a
    Denial of Service of the web framework and maybe inject arbitrary Ruby
    scripts.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://weblog.rubyonrails.org/2006/8/9/rails-1-1-5-mandatory-security-patch-and-other-tidbits
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8fe7cbd6"
  );
  # http://weblog.rubyonrails.org/2006/8/10/rails-1-1-6-backports-and-full-disclosure
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7eb1d7c6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200608-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ruby on Rails users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-ruby/rails-1.1.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rails");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-ruby/rails", unaffected:make_list("ge 1.1.6"), vulnerable:make_list("lt 1.1.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ruby on Rails");
}
