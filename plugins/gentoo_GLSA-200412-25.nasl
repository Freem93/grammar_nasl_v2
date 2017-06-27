#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200412-25.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16067);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");
  script_osvdb_id(12439, 12453, 12454);
  script_xref(name:"GLSA", value:"200412-25");

  script_name(english:"GLSA-200412-25 : CUPS: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200412-25
(CUPS: Multiple vulnerabilities)

    CUPS makes use of vulnerable Xpdf code to handle PDF files
    (CAN-2004-1125). Furthermore, Ariel Berkman discovered a buffer
    overflow in the ParseCommand function in hpgl-input.c in the hpgltops
    program (CAN-2004-1267). Finally, Bartlomiej Sieka discovered several
    problems in the lppasswd program: it ignores some write errors
    (CAN-2004-1268), it can leave the passwd.new file in place
    (CAN-2004-1269) and it does not verify that passwd.new file is
    different from STDERR (CAN-2004-1270).
  
Impact :

    The Xpdf and hpgltops vulnerabilities may be exploited by a remote
    attacker to execute arbitrary code by sending specific print jobs to a
    CUPS spooler. The lppasswd vulnerabilities may be exploited by a local
    attacker to write data to the CUPS password file or deny further
    password modifications.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://tigger.uic.edu/~jlongs2/holes/cups.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f172fa2d"
  );
  # http://tigger.uic.edu/~jlongs2/holes/cups2.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afff57c3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200412-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-print/cups-1.1.23'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-print/cups", unaffected:make_list("ge 1.1.23"), vulnerable:make_list("lt 1.1.23"))) flag++;

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
