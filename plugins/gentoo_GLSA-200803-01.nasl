#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31328);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-1199", "CVE-2007-5659", "CVE-2007-5663", "CVE-2007-5666", "CVE-2008-0655", "CVE-2008-0667", "CVE-2008-0726");
  script_bugtraq_id(27641);
  script_osvdb_id(33897, 41492, 41493, 41494, 41495, 46549);
  script_xref(name:"GLSA", value:"200803-01");

  script_name(english:"GLSA-200803-01 : Adobe Acrobat Reader: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200803-01
(Adobe Acrobat Reader: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Acrobat Reader,
    including:
    A file disclosure when using file:// in PDF documents
    (CVE-2007-1199)
    Multiple buffer overflows in unspecified JavaScript methods
    (CVE-2007-5659)
    An unspecified vulnerability in the Escript.api plugin
    (CVE-2007-5663)
    An untrusted search path (CVE-2007-5666)
    Incorrect handling of printers (CVE-2008-0667)
    An integer overflow when passing incorrect arguments to
    'printSepsWithParams' (CVE-2008-0726)
    Other unspecified vulnerabilities have also been reported
    (CVE-2008-0655).
  
Impact :

    A remote attacker could entice a user to open a specially crafted
    document, possibly resulting in the remote execution of arbitrary code
    with the privileges of the user running the application. A remote
    attacker could also perform cross-site request forgery attacks, or
    cause a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Acrobat Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-8.1.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Collab.collectEmailInfo() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/28");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 8.1.2"), vulnerable:make_list("lt 8.1.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Acrobat Reader");
}
