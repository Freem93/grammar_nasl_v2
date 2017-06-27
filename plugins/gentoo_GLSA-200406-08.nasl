#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200406-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14519);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0520");
  script_osvdb_id(6514);
  script_xref(name:"CERT-CC", value:"CA-2000-02");
  script_xref(name:"GLSA", value:"200406-08");

  script_name(english:"GLSA-200406-08 : Squirrelmail: Another XSS vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200406-08
(Squirrelmail: Another XSS vulnerability)

    A new cross-site scripting (XSS) vulnerability in
    Squirrelmail-1.4.3_rc1 has been discovered. In functions/mime.php
    Squirrelmail fails to properly sanitize user input.
  
Impact :

    By enticing a user to read a specially crafted e-mail, an attacker can
    execute arbitrary scripts running in the context of the victim's
    browser. This could lead to a compromise of the user's webmail account,
    cookie theft, etc.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200406-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SquirrelMail users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=mail-client/squirrelmail-1.4.3'
    # emerge '>=mail-client/squirrelmail-1.4.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-client/squirrelmail", unaffected:make_list("ge 1.4.3"), vulnerable:make_list("le 1.4.3_rc1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Squirrelmail");
}
