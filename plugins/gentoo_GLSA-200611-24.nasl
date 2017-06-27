#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200611-24.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(23746);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/04/28 18:42:39 $");

  script_cve_id("CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");
  script_osvdb_id(29005, 29006, 29007, 29008);
  script_xref(name:"GLSA", value:"200611-24");

  script_name(english:"GLSA-200611-24 : LHa: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200611-24
(LHa: Multiple vulnerabilities)

    Tavis Ormandy of the Google Security Team discovered several
    vulnerabilities in the LZH decompression component used by LHa. The
    make_table function of unlzh.c contains an array index error and a
    buffer overflow vulnerability. The build_tree function of unpack.c
    contains a buffer underflow vulnerability. Additionally, unlzh.c
    contains a code that could run in an infinite loop.
  
Impact :

    By enticing a user to uncompress a specially crafted archive, a remote
    attacker could cause a Denial of Service by CPU consumption or execute
    arbitrary code with the rights of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200611-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All LHa users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-arch/lha-114i-r6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lha");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/20");
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

if (qpkg_check(package:"app-arch/lha", unaffected:make_list("ge 114i-r6"), vulnerable:make_list("lt 114i-r6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LHa");
}
