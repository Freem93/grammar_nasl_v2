#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14547);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/22 14:14:42 $");

  script_cve_id("CVE-2004-0608");
  script_osvdb_id(7217);
  script_xref(name:"GLSA", value:"200407-14");

  script_name(english:"GLSA-200407-14 : Unreal Tournament 2003/2004: Buffer overflow in 'secure' queries");
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
"The remote host is affected by the vulnerability described in GLSA-200407-14
(Unreal Tournament 2003/2004: Buffer overflow in 'secure' queries)

    The Unreal-based game servers support a specific type of query called
    'secure'. Part of the Gamespy protocol, this query is used to ask if the
    game server is able to calculate an exact response using a provided string.
    Luigi Auriemma found that sending a long 'secure' query triggers a buffer
    overflow in the game server.
  
Impact :

    By sending a malicious UDP-based 'secure' query, an attacker could execute
    arbitrary code on the game server.
  
Workaround :

    Users can avoid this vulnerability by not using Unreal Tournament to host
    games as a server. All users running a server should upgrade to the latest
    versions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aluigi.altervista.org/adv/unsecure-adv.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Unreal Tournament users should upgrade to the latest available
    versions:
    # emerge sync
    # emerge -pv '>=games-fps/ut2003-2225-r3'
    # emerge '>=games-fps/ut2003-2225-r3'
    # emerge -pv '>=games-server/ut2003-ded-2225-r2'
    # emerge '>=games-server/ut2003-ded-2225-r2'
    # emerge -pv '>=games-fps/ut2004-3236'
    # emerge '>=games-fps/ut2004-3236'
    # emerge -pv '>=games-fps/ut2004-demo-3120-r4'
    # emerge '>=games-fps/ut2004-demo-3120-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Unreal Tournament 2004 "secure" Overflow (Win32)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ut2003");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ut2003-ded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ut2004");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ut2004-demo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"games-fps/ut2004-demo", unaffected:make_list("ge 3120-r4"), vulnerable:make_list("le 3120-r3"))) flag++;
if (qpkg_check(package:"games-server/ut2003-ded", unaffected:make_list("ge 2225-r2"), vulnerable:make_list("le 2225-r1"))) flag++;
if (qpkg_check(package:"games-fps/ut2003", unaffected:make_list("ge 2225-r3"), vulnerable:make_list("le 2225-r2"))) flag++;
if (qpkg_check(package:"games-fps/ut2004", unaffected:make_list("ge 3236"), vulnerable:make_list("lt 3236"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Unreal Tournament 2003/2004");
}
