#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200406-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14518);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0413");
  script_osvdb_id(6935);
  script_xref(name:"GLSA", value:"200406-07");

  script_name(english:"GLSA-200406-07 : Subversion: Remote heap overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200406-07
(Subversion: Remote heap overflow)

    The svn protocol parser trusts the indicated length of a URI string sent by
    a client. This allows a client to specify a very long string, thereby
    causing svnserve to allocate enough memory to hold that string. This may
    cause a Denial of Service. Alternately, given a string that causes an
    integer overflow in the variable holding the string length, the server
    might allocate less memory than required, allowing a heap overflow. This
    heap overflow may then be exploitable, allowing remote code execution. The
    attacker does not need read or write access to the Subversion repository
    being served, since even un-authenticated users can send svn protocol
    requests.
  
Impact :

    Ranges from remote Denial of Service to potential arbitrary code execution
    with privileges of the svnserve process.
  
Workaround :

    Servers without svnserve running are not vulnerable. Disable svnserve and
    use DAV for access instead."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200406-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest version of Subversion.
    # emerge sync
    # emerge -pv '>=dev-util/subversion-1.0.4-r1'
    # emerge '>=dev-util/subversion-1.0.4-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/12");
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

if (qpkg_check(package:"dev-util/subversion", unaffected:make_list("ge 1.0.4-r1"), vulnerable:make_list("le 1.0.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Subversion");
}
