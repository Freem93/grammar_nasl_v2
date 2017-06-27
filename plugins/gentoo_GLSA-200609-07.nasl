#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200609-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22352);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:56:51 $");

  script_cve_id("CVE-2006-3739", "CVE-2006-3740");
  script_bugtraq_id(19974);
  script_osvdb_id(28738, 28739);
  script_xref(name:"GLSA", value:"200609-07");

  script_name(english:"GLSA-200609-07 : LibXfont, monolithic X.org: Multiple integer overflows");
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
"The remote host is affected by the vulnerability described in GLSA-200609-07
(LibXfont, monolithic X.org: Multiple integer overflows)

    Several integer overflows have been found in the CID font parser.
  
Impact :

    A remote attacker could exploit this vulnerability by enticing a user
    to load a malicious font file resulting in the execution of arbitrary
    code with the permissions of the user running the X server which
    typically is the root user. A local user could exploit this
    vulnerability to gain elevated privileges.
  
Workaround :

    Disable CID-encoded Type 1 fonts by removing the 'type1' module and
    replacing it with the 'freetype' module in xorg.conf."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200609-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libXfont users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/libXfont-1.2.1'
    All monolithic X.org users are advised to migrate to modular X.org."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/12");
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

if (qpkg_check(package:"x11-libs/libXfont", unaffected:make_list("ge 1.2.1"), vulnerable:make_list("lt 1.2.1"))) flag++;
if (qpkg_check(package:"x11-base/xorg-x11", unaffected:make_list("ge 7.0"), vulnerable:make_list("lt 7.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibXfont / monolithic X.org");
}
