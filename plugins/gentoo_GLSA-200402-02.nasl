#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200402-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14446);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0083");
  script_xref(name:"GLSA", value:"200402-02");

  script_name(english:"GLSA-200402-02 : XFree86 Font Information File Buffer Overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200402-02
(XFree86 Font Information File Buffer Overflow)

    Exploitation of a buffer overflow in The XFree86 Window System
    discovered by iDefence allows local attackers to gain root
    privileges.
    The problem exists in the parsing of the 'font.alias' file. The X
    server (running as root) fails to check the length of the user
    provided input, so a malicious user may craft a malformed
    'font.alias' file causing a buffer overflow upon parsing,
    eventually leading to the execution of arbitrary code.
    To reproduce the overflow on the command line one can run:
    # cat > fonts.dir <<EOF
    1
    word.bdf -misc-fixed-medium-r-semicondensed--13-120-75-75-c-60-iso8859-1
    EOF
    # perl -e 'print '0' x 1024 . 'A' x 96 . '\\n'' > fonts.alias
    # X :0 -fp $PWD
    {Some output removed}... Server aborting... Segmentation fault (core dumped)
  
Impact :

    Successful exploitation can lead to a root compromise provided
    that the attacker is able to execute commands in the X11
    subsystem. This can be done either by having console access to the
    target or through a remote exploit against any X client program
    such as a web-browser, mail-reader or game.
  
Workaround :

    No immediate workaround is available; a software upgrade is required.
    Gentoo has released XFree 4.2.1-r3, 4.3.0-r4 and 4.3.99.902-r1 and
    encourages all users to upgrade their XFree86
    installations. Vulnerable versions are no longer available in
    Portage."
  );
  # http://www.idefense.com/application/poi/display?id=72&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8ff1873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200402-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users are recommended to upgrade their XFree86 installation:
    # emerge sync
    # emerge -pv x11-base/xfree
    # emerge x11-base/xfree"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xfree");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"x11-base/xfree", unaffected:make_list("eq 4.2.1-r3", "eq 4.3.0-r4", "ge 4.3.99.902-r1"), vulnerable:make_list("lt 4.3.99.902-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "x11-base/xfree");
}
