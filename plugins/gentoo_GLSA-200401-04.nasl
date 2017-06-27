#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200401-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14444);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200401-04");

  script_name(english:"GLSA-200401-04 : GAIM 0.75 Remote overflows");
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
"The remote host is affected by the vulnerability described in GLSA-200401-04
(GAIM 0.75 Remote overflows)

    Yahoo changed the authentication methods to their IM servers,
    rendering GAIM useless. The GAIM team released a rushed release
    solving this issue, however, at the same time a code audit
    revealed 12 new vulnerabilities.
  
Impact :

    Due to the nature of instant messaging many of these bugs require
    man-in-the-middle attacks between the client and the server. But
    the underlying protocols are easy to implement and attacking
    ordinary TCP sessions is a fairly simple task. As a result, all
    users are advised to upgrade their GAIM installation.
        Users of GAIM 0.74 or below are affected by 7 of the
        vulnerabilities and are encouraged to upgrade.
        Users of GAIM 0.75 are affected by 11 of the vulnerabilities
        and are encouraged to upgrade to the patched version of GAIM
        offered by Gentoo.
        Users of GAIM 0.75-r6 are only affected by
        4 of the vulnerabilities, but are still urged to upgrade to
        maintain security.
  
Workaround :

    There is no immediate workaround; a software upgrade is required."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/351235/2004-01-23/2004-01-29/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200401-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users are recommended to upgrade GAIM to 0.75-r7.
    $> emerge sync
    $> emerge -pv '>=net-im/gaim-0.75-r7'
    $> emerge '>=net-im/gaim-0.75-r7'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"net-im/gaim", unaffected:make_list("ge 0.75-r7"), vulnerable:make_list("lt 0.75-r7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-im/gaim");
}
