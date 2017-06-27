#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14476);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2004-0097");
  script_xref(name:"GLSA", value:"200404-11");

  script_name(english:"GLSA-200404-11 : Multiple Vulnerabilities in pwlib");
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
"The remote host is affected by the vulnerability described in GLSA-200404-11
(Multiple Vulnerabilities in pwlib)

    Multiple vulnerabilities have been found in the implementation of protocol
    H.323 contained in pwlib. Most of the vulnerabilies are in the parsing of
    ASN.1 elements which would allow an attacker to use a maliciously crafted
    ASN.1 element to cause unpredictable behavior in pwlib.
  
Impact :

    An attacker may cause a denial of service condition or cause a buffer
    overflow that would allow arbitrary code to be executed with root
    privileges.
  
Workaround :

    Blocking ports 1719 and 1720 may reduce the likelihood of an attack. All
    users are advised to upgrade to the latest version of the affected package."
  );
  # http://www.uniras.gov.uk/vuls/2004/006489/h323.htm
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc7c4598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All pwlib users are advised to upgrade to version 1.5.2-r3 or later:
    # emerge sync
    # emerge -pv '>=dev-libs/pwlib-1.5.2-r3'
    # emerge '>=dev-libs/pwlib-1.5.2-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pwlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/pwlib", unaffected:make_list("ge 1.5.2-r3"), vulnerable:make_list("le 1.5.2-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-libs/pwlib");
}
