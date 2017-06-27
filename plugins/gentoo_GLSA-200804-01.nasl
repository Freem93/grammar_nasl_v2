#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31752);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_cve_id("CVE-2008-0047", "CVE-2008-0053", "CVE-2008-0882", "CVE-2008-1373");
  script_bugtraq_id(27906, 28307, 28334, 28544);
  script_osvdb_id(43376, 44160);
  script_xref(name:"GLSA", value:"200804-01");

  script_name(english:"GLSA-200804-01 : CUPS: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200804-01
(CUPS: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in CUPS:
    regenrecht (VeriSign iDefense) discovered that the
    cgiCompileSearch() function used in several CGI scripts in CUPS'
    administration interface does not correctly calculate boundaries when
    processing a user-provided regular expression, leading to a heap-based
    buffer overflow (CVE-2008-0047).
    Helge Blischke reported a
    double free() vulnerability in the process_browse_data() function when
    adding or removing remote shared printers (CVE-2008-0882).
    Tomas Hoger (Red Hat) reported that the gif_read_lzw() function
    uses the code_size value from GIF images without properly checking it,
    leading to a buffer overflow (CVE-2008-1373).
    An unspecified
    input validation error was discovered in the HP-GL/2 filter
    (CVE-2008-0053).
  
Impact :

    A local attacker could send specially crafted network packets or print
    jobs and possibly execute arbitrary code with the privileges of the
    user running CUPS (usually lp), or cause a Denial of Service. The
    vulnerabilities are exploitable via the network when CUPS is sharing
    printers remotely.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-print/cups-1.2.12-r7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-print/cups", unaffected:make_list("ge 1.2.12-r7"), vulnerable:make_list("lt 1.2.12-r7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CUPS");
}
