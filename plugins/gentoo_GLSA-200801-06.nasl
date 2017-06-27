#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200801-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(29910);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:24 $");

  script_cve_id("CVE-2007-6531", "CVE-2007-6532");
  script_osvdb_id(43422, 43424);
  script_xref(name:"GLSA", value:"200801-06");

  script_name(english:"GLSA-200801-06 : Xfce: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200801-06
(Xfce: Multiple vulnerabilities)

    Gregory Andersen reported that the Xfce4 panel does not correctly
    calculate memory boundaries, leading to a stack-based buffer overflow
    in the launcher_update_panel_entry() function (CVE-2007-6531). Daichi
    Kawahata reported libxfcegui4 did not copy provided values when
    creating 'SessionClient' structs, possibly leading to access of freed
    memory areas (CVE-2007-6532).
  
Impact :

    A remote attacker could entice a user to install a specially crafted
    'rc' file to execute arbitrary code via long strings in the 'Name' and
    'Comment' fields or via unspecified vectors involving the second
    vulnerability.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200801-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xfce4 panel users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=xfce-base/xfce4-panel-4.4.2'
    All libxfcegui4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=xfce-base/libxfcegui4-4.4.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libxfcegui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xfce4-panel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
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

if (qpkg_check(package:"xfce-base/libxfcegui4", unaffected:make_list("ge 4.4.2"), vulnerable:make_list("lt 4.4.2"))) flag++;
if (qpkg_check(package:"xfce-base/xfce4-panel", unaffected:make_list("ge 4.4.2"), vulnerable:make_list("lt 4.4.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xfce");
}
