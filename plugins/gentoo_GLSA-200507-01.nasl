#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18605);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/06/14 17:29:37 $");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);
  script_osvdb_id(17793);
  script_xref(name:"GLSA", value:"200507-01");

  script_name(english:"GLSA-200507-01 : PEAR XML-RPC, phpxmlrpc: PHP script injection vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200507-01
(PEAR XML-RPC, phpxmlrpc: PHP script injection vulnerability)

    James Bercegay of GulfTech Security Research discovered that the
    PEAR XML-RPC and phpxmlrpc libraries fail to sanatize input sent using
    the 'POST' method.
  
Impact :

    A remote attacker could exploit this vulnerability to execute
    arbitrary PHP script code by sending a specially crafted XML document
    to web applications making use of these libraries.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gulftech.org/?node=research&article_id=00088-07022005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PEAR-XML_RPC users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/PEAR-XML_RPC-1.3.1'
    All phpxmlrpc users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/phpxmlrpc-1.1.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:PEAR-XML_RPC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpxmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-php/PEAR-XML_RPC", unaffected:make_list("ge 1.3.1"), vulnerable:make_list("lt 1.3.1"))) flag++;
if (qpkg_check(package:"dev-php/phpxmlrpc", unaffected:make_list("ge 1.1.1"), vulnerable:make_list("lt 1.1.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PEAR XML-RPC / phpxmlrpc");
}
