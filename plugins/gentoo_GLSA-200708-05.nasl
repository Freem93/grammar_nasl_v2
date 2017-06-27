#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200708-05.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25870);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_cve_id("CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3474", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");
  script_osvdb_id(37740, 37741, 37742, 37743, 37744, 37745);
  script_xref(name:"GLSA", value:"200708-05");

  script_name(english:"GLSA-200708-05 : GD: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200708-05
(GD: Multiple vulnerabilities)

    Xavier Roche discovered an infinite loop in the gdPngReadData()
    function when processing a truncated PNG file (CVE-2007-2756). An
    integer overflow has been discovered in the gdImageCreateTrueColor()
    function (CVE-2007-3472). An error has been discovered in the function
    gdImageCreateXbm() function (CVE-2007-3473). Unspecified
    vulnerabilities have been discovered in the GIF reader (CVE-2007-3474).
    An error has been discovered when processing a GIF image that has no
    global color map (CVE-2007-3475). An array index error has been
    discovered in the file gd_gif_in.c when processing images with an
    invalid color index (CVE-2007-3476). An error has been discovered in
    the imagearc() and imagefilledarc() functions when processing overly
    large angle values (CVE-2007-3477). A race condition has been
    discovered in the gdImageStringFTEx() function (CVE-2007-3478).
  
Impact :

    A remote attacker could exploit one of these vulnerabilities to cause a
    Denial of Service or possibly execute arbitrary code with the
    privileges of the user running GD.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200708-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gd-2.0.35'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/gd", unaffected:make_list("ge 2.0.35"), vulnerable:make_list("lt 2.0.35"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GD");
}
