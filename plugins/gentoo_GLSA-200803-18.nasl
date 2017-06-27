#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-18.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31444);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-0783", "CVE-2008-0784", "CVE-2008-0785", "CVE-2008-0786");
  script_osvdb_id(41739, 41740, 41741, 41781, 41782, 41783, 41784, 41785, 41793);
  script_xref(name:"GLSA", value:"200803-18");

  script_name(english:"GLSA-200803-18 : Cacti: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200803-18
(Cacti: Multiple vulnerabilities)

    The following inputs are not properly sanitized before being processed:
    'view_type' parameter in the file graph.php, 'filter' parameter
    in the file graph_view.php, 'action' and 'login_username' parameters in
    the file index.php (CVE-2008-0783).
    'local_graph_id' parameter in the file graph.php
    (CVE-2008-0784).
    'graph_list' parameter in the file graph_view.php, 'leaf_id' and
    'id' parameters in the file tree.php, 'local_graph_id' in the file
    graph_xport.php (CVE-2008-0785).
    Furthermore, CRLF injection attack are possible via unspecified vectors
    (CVE-2008-0786).
  
Impact :

    A remote attacker could exploit these vulnerabilities, leading to path
    disclosure, Cross-Site Scripting attacks, SQL injection, and HTTP
    response splitting.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Cacti users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/cacti-0.8.7b'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(79, 89, 94, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/10");
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

if (qpkg_check(package:"net-analyzer/cacti", unaffected:make_list("ge 0.8.7b", "rge 0.8.6j-r8"), vulnerable:make_list("lt 0.8.7b"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cacti");
}
