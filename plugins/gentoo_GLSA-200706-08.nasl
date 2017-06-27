#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200706-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25593);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789");
  script_osvdb_id(35483, 36199, 36200, 36201, 36202);
  script_xref(name:"GLSA", value:"200706-08");

  script_name(english:"GLSA-200706-08 : emul-linux-x86-java: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200706-08
(emul-linux-x86-java: Multiple vulnerabilities)

    Chris Evans of the Google Security Team has discovered an integer
    overflow in the ICC parser, and another vulnerability in the BMP
    parser. An unspecified vulnerability involving an 'incorrect use of
    system classes' was reported by the Fujitsu security team.
  
Impact :

    A remote attacker could entice a user to open a specially crafted
    image, possibly resulting in the execution of arbitrary code with the
    privileges of the user running Emul-linux-x86-java. They also could
    entice a user to open a specially crafted BMP image, resulting in a
    Denial of Service. Note that these vulnerabilities may also be
    triggered by a tool processing image files automatically.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200706-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Emul-linux-x86-java users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.5.0.11'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulation/emul-linux-x86-java", unaffected:make_list("ge 1.5.0.11", "rge 1.4.2.16", "rge 1.4.2.17", "rge 1.4.2.19"), vulnerable:make_list("lt 1.5.0.11"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emul-linux-x86-java");
}
