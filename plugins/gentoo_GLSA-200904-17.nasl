#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200904-17.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(36196);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-0193", "CVE-2009-0658", "CVE-2009-0927", "CVE-2009-0928", "CVE-2009-1061", "CVE-2009-1062");
  script_bugtraq_id(33751, 34169, 34229);
  script_osvdb_id(52073, 53644, 53645, 53646, 53647, 53648);
  script_xref(name:"GLSA", value:"200904-17");
  script_xref(name:"TRA", value:"TRA-2009-01");

  script_name(english:"GLSA-200904-17 : Adobe Reader: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200904-17
(Adobe Reader: User-assisted execution of arbitrary code)

    Multiple vulnerabilities have been discovered in Adobe Reader:
    Alin Rad Pop of Secunia Research reported a heap-based buffer overflow
    when processing PDF files containing a malformed JBIG2 symbol
    dictionary segment (CVE-2009-0193).
    A buffer overflow related to a non-JavaScript function call and
    possibly an embedded JBIG2 image stream has been reported
    (CVE-2009-0658).
    Tenable Network Security reported a stack-based buffer overflow that
    can be triggered via a crafted argument to the getIcon() method of a
    Collab object (CVE-2009-0927).
    Sean Larsson of iDefense Labs reported a heap-based buffer overflow
    when processing a PDF file containing a JBIG2 stream with a size
    inconsistency related to an unspecified table (CVE-2009-0928).
    Jonathan Brossard of the iViZ Security Research Team reported an
    unspecified vulnerability related to JBIG2 and input validation
    (CVE-2009-1061).
    Will Dormann of CERT/CC reported a vulnerability lading to memory
    corruption related to JBIG2 (CVE-2009-1062).
  
Impact :

    A remote attacker could entice a user to open a specially crafted PDF
    document, possibly leading to the execution of arbitrary code with the
    privileges of the user running the application, or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200904-17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2009-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-8.1.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Collab.getIcon() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 8.1.4"), vulnerable:make_list("lt 8.1.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Reader");
}
