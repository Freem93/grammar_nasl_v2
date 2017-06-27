#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200511-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20234);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3354");
  script_osvdb_id(20675);
  script_xref(name:"GLSA", value:"200511-13");

  script_name(english:"GLSA-200511-13 : Sylpheed, Sylpheed-Claws: Buffer overflow in LDIF importer");
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
"The remote host is affected by the vulnerability described in GLSA-200511-13
(Sylpheed, Sylpheed-Claws: Buffer overflow in LDIF importer)

    Colin Leroy reported buffer overflow vulnerabilities in Sylpheed
    and Sylpheed-Claws. The LDIF importer uses a fixed length buffer to
    store data of variable length. Two similar problems exist also in the
    Mutt and Pine addressbook importers of Sylpheed-Claws.
  
Impact :

    By convincing a user to import a specially crafted LDIF file into
    the address book, a remote attacker could cause the program to crash,
    potentially allowing the execution of arbitrary code with the
    privileges of the user running the software.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200511-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sylpheed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/sylpheed-2.0.4'
    All Sylpheed-Claws users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/sylpheed-claws-1.0.5-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sylpheed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sylpheed-claws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/08");
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

if (qpkg_check(package:"mail-client/sylpheed", unaffected:make_list("ge 2.0.4"), vulnerable:make_list("lt 2.0.4"))) flag++;
if (qpkg_check(package:"mail-client/sylpheed-claws", unaffected:make_list("ge 1.0.5-r1"), vulnerable:make_list("lt 1.0.5-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sylpheed / Sylpheed-Claws");
}
