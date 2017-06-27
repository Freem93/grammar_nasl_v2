#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16398);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2004-1187", "CVE-2004-1188", "CVE-2004-1300");
  script_osvdb_id(12474, 12661, 12662);
  script_xref(name:"GLSA", value:"200501-07");

  script_name(english:"GLSA-200501-07 : xine-lib: Multiple overflows");
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
"The remote host is affected by the vulnerability described in GLSA-200501-07
(xine-lib: Multiple overflows)

    Ariel Berkman discovered that xine-lib reads specific input data
    into an array without checking the input size in demux_aiff.c, making
    it vulnerable to a buffer overflow (CAN-2004-1300) . iDefense
    discovered that the PNA_TAG handling code in pnm_get_chunk() does not
    check if the input size is larger than the buffer size (CAN-2004-1187).
    iDefense also discovered that in this same function, a negative value
    could be given to an unsigned variable that specifies the read length
    of input data (CAN-2004-1188).
  
Impact :

    A remote attacker could craft a malicious movie or convince a
    targeted user to connect to a malicious PNM server, which could result
    in the execution of arbitrary code with the rights of the user running
    any xine-lib frontend.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.idefense.com/application/poi/display?id=176&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8cbc267"
  );
  # http://www.idefense.com/application/poi/display?id=177&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ec1b810"
  );
  # http://tigger.uic.edu/~jlongs2/holes/xine-lib.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8a7e424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-libs/xine-lib"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/16");
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

if (qpkg_check(package:"media-libs/xine-lib", unaffected:make_list("ge 1_rc8-r1", "rge 1_rc6-r1"), vulnerable:make_list("lt 1_rc8-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xine-lib");
}
