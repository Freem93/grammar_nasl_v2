#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200801-09.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(30033);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_bugtraq_id(27350);
  script_osvdb_id(40938, 40939, 40940, 40941, 40942, 40943, 40944);
  script_xref(name:"GLSA", value:"200801-09");

  script_name(english:"GLSA-200801-09 : X.Org X server and Xfont library: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200801-09
(X.Org X server and Xfont library: Multiple vulnerabilities)

    regenrecht reported multiple vulnerabilities in various X server
    extension via iDefense:
    The XFree86-Misc extension does not properly sanitize a parameter
    within a PassMessage request, allowing the modification of a function
    pointer (CVE-2007-5760).
    Multiple functions in the XInput extension do not properly sanitize
    client requests for swapping bytes, leading to corruption of heap
    memory (CVE-2007-6427).
    Integer overflow vulnerabilities in the EVI extension and in the
    MIT-SHM extension can lead to buffer overflows (CVE-2007-6429).
    The TOG-CUP extension does not sanitize an index value in the
    ProcGetReservedColormapEntries() function, leading to arbitrary memory
    access (CVE-2007-6428).
    A buffer overflow was discovered in the Xfont library when
    processing PCF font files (CVE-2008-0006).
    The X server does not enforce restrictions when a user specifies a
    security policy file and attempts to open it (CVE-2007-5958).
  
Impact :

    Remote attackers could exploit the vulnerability in the Xfont library
    by enticing a user to load a specially crafted PCF font file resulting
    in the execution of arbitrary code with the privileges of the user
    running the X server, typically root. Local attackers could exploit
    this and the vulnerabilities in the X.org extensions to gain elevated
    privileges. If the X server allows connections from the network, these
    vulnerabilities could be exploited remotely. A local attacker could
    determine the existence of arbitrary files by exploiting the last
    vulnerability or possibly cause a Denial of Service.
  
Workaround :

    Workarounds for some of the vulnerabilities can be found in the X.Org
    security advisory as listed under References."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.freedesktop.org/archives/xorg/2008-January/031918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200801-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All X.Org X server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.3.0.0-r5'
    All X.Org Xfont library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/libXfont-1.3.1-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-base/xorg-server", unaffected:make_list("ge 1.3.0.0-r5"), vulnerable:make_list("lt 1.3.0.0-r5"))) flag++;
if (qpkg_check(package:"x11-libs/libXfont", unaffected:make_list("ge 1.3.1-r1"), vulnerable:make_list("lt 1.3.1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X.Org X server and Xfont library");
}
