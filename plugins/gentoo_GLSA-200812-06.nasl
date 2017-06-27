#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200812-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35023);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-3281", "CVE-2008-3529", "CVE-2008-4225", "CVE-2008-4226", "CVE-2008-4409");
  script_bugtraq_id(30783, 31126, 32326, 32331);
  script_osvdb_id(47636, 48158, 48754, 49992, 49993);
  script_xref(name:"GLSA", value:"200812-06");

  script_name(english:"GLSA-200812-06 : libxml2: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200812-06
(libxml2: Multiple vulnerabilities)

    Multiple vulnerabilities were reported in libxml2:
    Andreas Solberg reported that libxml2 does not properly detect
    recursion during entity expansion in an attribute value
    (CVE-2008-3281).
    A heap-based buffer overflow has been reported in the
    xmlParseAttValueComplex() function in parser.c (CVE-2008-3529).
    Christian Weiske reported that predefined entity definitions in
    entities are not properly handled (CVE-2008-4409).
    Drew Yao of Apple Product Security reported an integer overflow in the
    xmlBufferResize() function that can lead to an infinite loop
    (CVE-2008-4225).
    Drew Yao of Apple Product Security reported an integer overflow in the
    xmlSAX2Characters() function leading to a memory corruption
    (CVE-2008-4226).
  
Impact :

    A remote attacker could entice a user or automated system to open a
    specially crafted XML document with an application using libxml2,
    possibly resulting in the exeution of arbitrary code or a high CPU and
    memory consumption.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200812-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libxml2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/libxml2-2.7.2-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/03");
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

if (qpkg_check(package:"dev-libs/libxml2", unaffected:make_list("ge 2.7.2-r1"), vulnerable:make_list("lt 2.7.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
