#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200508-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19388);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-2471");
  script_bugtraq_id(14379);
  script_osvdb_id(18253);
  script_xref(name:"GLSA", value:"200508-04");

  script_name(english:"GLSA-200508-04 : Netpbm: Arbitrary code execution in pstopnm");
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
"The remote host is affected by the vulnerability described in GLSA-200508-04
(Netpbm: Arbitrary code execution in pstopnm)

    Max Vozeler reported that pstopnm calls the GhostScript interpreter on
    untrusted PostScript files without specifying the -dSAFER option, to
    convert a PostScript file into a PBM, PGM, or PNM file.
  
Impact :

    An attacker could craft a malicious PostScript file and entice a user
    to run pstopnm on it, resulting in the execution of arbitrary commands
    with the permissions of the user running pstopnm.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/16184/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200508-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Netpbm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-libs/netpbm"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:netpbm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/netpbm", unaffected:make_list("ge 10.28", "rge 10.26.32", "rge 10.26.33", "rge 10.26.42", "rge 10.26.43", "rge 10.26.44", "rge 10.26.48", "rge 10.26.49", "rge 10.26.59", "rge 10.26.61"), vulnerable:make_list("lt 10.28"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Netpbm");
}
