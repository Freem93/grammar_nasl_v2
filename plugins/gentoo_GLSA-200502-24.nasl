#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200502-24.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17138);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1092", "CVE-2004-1176");
  script_osvdb_id(12902, 12903, 12907, 12911);
  script_xref(name:"GLSA", value:"200502-24");

  script_name(english:"GLSA-200502-24 : Midnight Commander: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200502-24
(Midnight Commander: Multiple vulnerabilities)

    Midnight Commander contains several format string vulnerabilities
    (CAN-2004-1004), buffer overflows (CAN-2004-1005), a memory
    deallocation error (CAN-2004-1092) and a buffer underflow
    (CAN-2004-1176).
  
Impact :

    An attacker could exploit these vulnerabilities to execute
    arbitrary code with the permissions of the user running Midnight
    Commander or cause Denial of Service by freeing unallocated memory.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200502-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Midnight Commander users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-misc/mc-4.6.0-r13'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-misc/mc", unaffected:make_list("ge 4.6.0-r13"), vulnerable:make_list("lt 4.6.0-r13"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Midnight Commander");
}
