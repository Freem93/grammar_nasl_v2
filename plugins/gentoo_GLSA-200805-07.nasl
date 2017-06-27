#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200805-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32209);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_bugtraq_id(23283, 23300, 24074);
  script_osvdb_id(29262, 34107, 34108, 34917, 34918, 36196, 36509, 37055, 37726, 37895, 38272, 38273, 38274, 40938, 40939, 40940, 40941, 40942, 40943, 40944);
  script_xref(name:"GLSA", value:"200805-07");

  script_name(english:"GLSA-200805-07 : Linux Terminal Server Project: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200805-07
(Linux Terminal Server Project: Multiple vulnerabilities)

    LTSP version 4.2, ships prebuilt copies of programs such as the Linux
    Kernel, the X.org X11 server (GLSA 200705-06, GLSA 200710-16, GLSA
    200801-09), libpng (GLSA 200705-24, GLSA 200711-08), Freetype (GLSA
    200705-02, GLSA 200705-22) and OpenSSL (GLSA 200710-06, GLSA 200710-30)
    which were subject to multiple security vulnerabilities since 2006.
    Please note that the given list of vulnerabilities might not be
    exhaustive.
  
Impact :

    A remote attacker could possibly exploit vulnerabilities in the
    aforementioned programs and execute arbitrary code, disclose sensitive
    data or cause a Denial of Service within LTSP 4.2 clients.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200705-02.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200705-06.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200705-22.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200705-24.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200710-06.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200710-16.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200710-30.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200711-08.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200801-09.xml"
  );
  # https://bugs.gentoo.org/177580
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.gentoo.org/show_bug.cgi?id=177580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200805-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"LTSP 4.2 is not maintained upstream in favor of version 5. Since
    version 5 is not yet available in Gentoo, the package has been masked.
    We recommend that users unmerge LTSP:
    # emerge --unmerge net-misc/ltsp
    If you have a requirement for Linux Terminal Servers, please either set
    up a terminal server by hand or use one of the distributions that
    already migrated to LTSP 5. If you want to contribute to the
    integration of LTSP 5 in Gentoo, or want to follow its development,
    find details in bug 177580."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ltsp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/ltsp", unaffected:make_list(), vulnerable:make_list("lt 5.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Linux Terminal Server Project");
}
