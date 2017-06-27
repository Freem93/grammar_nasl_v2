#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-21.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31447);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-1167", "CVE-2008-1168");
  script_osvdb_id(42906, 42907);
  script_xref(name:"GLSA", value:"200803-21");

  script_name(english:"GLSA-200803-21 : Sarg: Remote execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200803-21
(Sarg: Remote execution of arbitrary code)

    Sarg doesn't properly check its input for abnormal content when
    processing Squid log files.
  
Impact :

    A remote attacker using a vulnerable Squid as a proxy server or a
    reverse-proxy server can inject arbitrary content into the 'User-Agent'
    HTTP client header, that will be processed by sarg, which will lead to
    the execution of arbitrary code, or JavaScript injection, allowing
    Cross-Site Scripting attacks and the theft of credentials.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All sarg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/sarg-2.2.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sarg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
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

if (qpkg_check(package:"net-analyzer/sarg", unaffected:make_list("ge 2.2.5"), vulnerable:make_list("lt 2.2.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sarg");
}
