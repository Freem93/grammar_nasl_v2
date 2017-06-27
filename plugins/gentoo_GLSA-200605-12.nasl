#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200605-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21354);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-2236");
  script_bugtraq_id(17857);
  script_osvdb_id(25279);
  script_xref(name:"GLSA", value:"200605-12");

  script_name(english:"GLSA-200605-12 : Quake 3 engine based games: Buffer Overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200605-12
(Quake 3 engine based games: Buffer Overflow)

    landser discovered a vulnerability within the 'remapShader'
    command. Due to a boundary handling error in 'remapShader', there is a
    possibility of a buffer overflow.
  
Impact :

    An attacker could set up a malicious game server and entice users
    to connect to it, potentially resulting in the execution of arbitrary
    code with the rights of the game user.
  
Workaround :

    Do not connect to untrusted game servers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200605-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Quake 3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-fps/quake3-bin-1.32c'
    All RTCW users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-fps/rtcw-1.41b'
    All Enemy Territory users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-fps/enemy-territory-2.60b'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:enemy-territory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:quake3-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rtcw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/05");
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

if (qpkg_check(package:"games-fps/quake3-bin", unaffected:make_list("ge 1.32c"), vulnerable:make_list("lt 1.32c"))) flag++;
if (qpkg_check(package:"games-fps/enemy-territory", unaffected:make_list("ge 2.60b"), vulnerable:make_list("lt 2.60b"))) flag++;
if (qpkg_check(package:"games-fps/rtcw", unaffected:make_list("ge 1.41b"), vulnerable:make_list("lt 1.41b"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Quake 3 engine based games");
}
