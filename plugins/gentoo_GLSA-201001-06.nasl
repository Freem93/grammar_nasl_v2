#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201001-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(44895);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/13 14:12:00 $");

  script_cve_id("CVE-2009-3575", "CVE-2009-3617");
  script_osvdb_id(58708, 59087);
  script_xref(name:"GLSA", value:"201001-06");

  script_name(english:"GLSA-201001-06 : aria2: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201001-06
(aria2: Multiple vulnerabilities)

    Tatsuhiro Tsujikawa reported a buffer overflow in
    DHTRoutingTableDeserializer.cc (CVE-2009-3575) and a format string
    vulnerability in the AbstractCommand::onAbort() function in
    src/AbstractCommand.cc (CVE-2009-3617).
  
Impact :

    A remote, unauthenticated attacker could possibly execute arbitrary
    code with the privileges of the user running the application or cause a
    Denial of Service (application crash).
  
Workaround :

    Do not use DHT (CVE-2009-3575) and disable logging (CVE-2009-3617)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201001-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All aria2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/aria2-1.6.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aria2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/aria2", unaffected:make_list("ge 1.6.3"), vulnerable:make_list("lt 1.6.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aria2");
}
