#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200602-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20953);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/17 13:39:45 $");

  script_cve_id("CVE-2006-0225");
  script_osvdb_id(22692);
  script_xref(name:"GLSA", value:"200602-11");

  script_name(english:"GLSA-200602-11 : OpenSSH, Dropbear: Insecure use of system() call");
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
"The remote host is affected by the vulnerability described in GLSA-200602-11
(OpenSSH, Dropbear: Insecure use of system() call)

    To copy from a local filesystem to another local filesystem, scp
    constructs a command line using 'cp' which is then executed via
    system(). Josh Bressers discovered that special characters are not
    escaped by scp, but are simply passed to the shell.
  
Impact :

    By tricking other users or applications to use scp on maliciously
    crafted filenames, a local attacker user can execute arbitrary commands
    with the rights of the user running scp.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200602-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSH users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/openssh-4.2_p1-r1'
    All Dropbear users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/dropbear-0.47-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dropbear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/dropbear", unaffected:make_list("ge 0.47-r1"), vulnerable:make_list("lt 0.47-r1"))) flag++;
if (qpkg_check(package:"net-misc/openssh", unaffected:make_list("ge 4.2_p1-r1"), vulnerable:make_list("lt 4.2_p1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenSSH / Dropbear");
}
