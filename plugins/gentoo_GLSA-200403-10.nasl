#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200403-10.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14461);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2003-0792");
  script_xref(name:"GLSA", value:"200403-10");

  script_name(english:"GLSA-200403-10 : Fetchmail 6.2.5 fixes a remote DoS");
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
"The remote host is affected by the vulnerability described in GLSA-200403-10
(Fetchmail 6.2.5 fixes a remote DoS)

    Fetchmail versions 6.2.4 and earlier can be crashed by sending a
    specially crafted email to a Fetchmail user. This problem occurs because
    Fetchmail does not properly allocate memory for long lines in an incoming
    email.
  
Impact :

    Fetchmail users who receive a malicious email may have their Fetchmail program crash.
  
Workaround :

    While a workaround is not currently known for this issue, all users are advised to upgrade to the latest version of Fetchmail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xforce.iss.net/xforce/xfdb/13450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200403-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Fetchmail users should upgrade to version 6.2.5 or later:
    # emerge sync
    # emerge -pv '>=net-mail/fetchmail-6.2.5'
    # emerge '>=net-mail/fetchmail-6.2.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/30");
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

if (qpkg_check(package:"net-mail/fetchmail", unaffected:make_list("ge 6.2.5"), vulnerable:make_list("le 6.2.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-mail/fetchmail");
}
