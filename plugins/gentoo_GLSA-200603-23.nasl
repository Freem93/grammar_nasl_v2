#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200603-23.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21147);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2006-1390");
  script_osvdb_id(24104, 24105);
  script_xref(name:"GLSA", value:"200603-23");

  script_name(english:"GLSA-200603-23 : NetHack, Slash'EM, Falcon's Eye: Local privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200603-23
(NetHack, Slash'EM, Falcon's Eye: Local privilege escalation)

    NetHack, Slash'EM and Falcon's Eye have been found to be incompatible
    with the system used for managing games on Gentoo Linux. As a result,
    they cannot be played securely on systems with multiple users.
  
Impact :

    A local user who is a member of group 'games' may be able to modify the
    state data used by NetHack, Slash'EM or Falcon's Eye to trigger the
    execution of arbitrary code with the privileges of other players.
    Additionally, the games may create save game files in a manner not
    suitable for use on Gentoo Linux, potentially allowing a local user to
    create or overwrite files with the permissions of other players.
  
Workaround :

    Do not add untrusted users to the 'games' group."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200603-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"NetHack has been masked in Portage pending the resolution of these
    issues. Vulnerable NetHack users are advised to uninstall the package
    until further notice.
    # emerge --ask --verbose --unmerge 'games-roguelike/nethack'
    Slash'EM has been masked in Portage pending the resolution of these
    issues. Vulnerable Slash'EM users are advised to uninstall the package
    until further notice.
    # emerge --ask --verbose --unmerge 'games-roguelike/slashem'
    Falcon's Eye has been masked in Portage pending the resolution of these
    issues. Vulnerable Falcon's Eye users are advised to uninstall the
    package until further notice.
    # emerge --ask --verbose --unmerge 'games-roguelike/falconseye'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:falconseye");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nethack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:slashem");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/10");
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

if (qpkg_check(package:"games-roguelike/slashem", unaffected:make_list(), vulnerable:make_list("le 0.0.760"))) flag++;
if (qpkg_check(package:"games-roguelike/falconseye", unaffected:make_list(), vulnerable:make_list("le 1.9.4a"))) flag++;
if (qpkg_check(package:"games-roguelike/nethack", unaffected:make_list(), vulnerable:make_list("le 3.4.3-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetHack / Slash'EM / Falcon's Eye");
}
