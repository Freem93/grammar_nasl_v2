#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200603-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21048);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2006-1100", "CVE-2006-1101", "CVE-2006-1102");
  script_osvdb_id(23713, 23714, 23715);
  script_xref(name:"GLSA", value:"200603-10");

  script_name(english:"GLSA-200603-10 : Cube: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200603-10
(Cube: Multiple vulnerabilities)

    Luigi Auriemma reported that Cube is vulnerable to a buffer
    overflow in the sgetstr() function (CVE-2006-1100) and that the
    sgetstr() and getint() functions fail to verify the length of the
    supplied argument, possibly leading to the access of invalid memory
    regions (CVE-2006-1101). Furthermore, he discovered that a client
    crashes when asked to load specially crafted mapnames (CVE-2006-1102).
  
Impact :

    A remote attacker could exploit the buffer overflow to execute
    arbitrary code with the rights of the user running cube. An attacker
    could also exploit the other vulnerabilities to crash a Cube client or
    server, resulting in a Denial of Service.
  
Workaround :

    Play solo games or restrict your multiplayer games to trusted
    parties."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200603-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upstream stated that there will be no fixed version of Cube, thus
    the Gentoo Security Team decided to hardmask Cube for security reasons.
    All Cube users are encouraged to uninstall Cube:
    # emerge --ask --unmerge games-fps/cube"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cube");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"games-fps/cube", unaffected:make_list(), vulnerable:make_list("le 20050829"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cube");
}
