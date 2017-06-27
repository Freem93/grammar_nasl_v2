#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201211-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(62867);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/13 14:19:45 $");

  script_cve_id("CVE-2010-3303", "CVE-2010-3763", "CVE-2010-4348", "CVE-2010-4349", "CVE-2010-4350", "CVE-2011-2938", "CVE-2011-3356", "CVE-2011-3357", "CVE-2011-3358", "CVE-2011-3578", "CVE-2011-3755", "CVE-2012-1118", "CVE-2012-1119", "CVE-2012-1120", "CVE-2012-1121", "CVE-2012-1122", "CVE-2012-1123", "CVE-2012-2691", "CVE-2012-2692");
  script_bugtraq_id(43604, 43837, 45399, 49235, 49448, 52313, 53907, 53921, 56467);
  script_osvdb_id(68388, 68389, 68390, 68391, 70155, 70156, 70157, 74566, 75126, 75127, 75128, 75129, 75130, 75131, 75295, 75296, 75646, 75829, 79831, 79832, 79833, 79834, 82838, 83166, 83223, 83271);
  script_xref(name:"GLSA", value:"201211-01");

  script_name(english:"GLSA-201211-01 : MantisBT: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201211-01
(MantisBT: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MantisBT. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could exploit these vulnerabilities to conduct
      directory traversal attacks, disclose the contents of local files, inject
      arbitrary web scripts, obtain sensitive information, bypass
      authentication and intended access restrictions, or manipulate bugs and
      attachments.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201211-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MantisBT users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mantisbt-1.2.11'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Mantisbt < 1.2.4 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mantisbt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/mantisbt", unaffected:make_list("ge 1.2.11"), vulnerable:make_list("lt 1.2.11"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MantisBT");
}
