#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200703-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24772);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:56:53 $");

  script_bugtraq_id(21240, 22396, 22566, 22694);
  script_xref(name:"GLSA", value:"200703-05");

  script_name(english:"GLSA-200703-05 : Mozilla Suite: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200703-05
(Mozilla Suite: Multiple vulnerabilities)

    Several vulnerabilities ranging from code execution with elevated
    privileges to information leaks affect the Mozilla Suite.
  
Impact :

    A remote attacker could entice a user to browse to a specially crafted
    website or open a specially crafted mail that could trigger some of the
    vulnerabilities, potentially allowing execution of arbitrary code,
    denials of service, information leaks, or cross-site scripting attacks
    leading to the robbery of cookies of authentication credentials.
  
Workaround :

    Most of the issues, but not all of them, can be prevented by disabling
    the HTML rendering in the mail client and JavaScript on every
    application."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f20085f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200703-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"The Mozilla Suite is no longer supported and has been masked after some
    necessary changes on all the other ebuilds which used to depend on it.
    Mozilla Suite users should unmerge www-client/mozilla or
    www-client/mozilla-bin, and switch to a supported product, like
    SeaMonkey, Thunderbird or Firefox.
    # emerge --unmerge 'www-client/mozilla'
    # emerge --unmerge 'www-client/mozilla-bin'"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/mozilla", unaffected:make_list(), vulnerable:make_list("le 1.7.13"))) flag++;
if (qpkg_check(package:"www-client/mozilla-bin", unaffected:make_list(), vulnerable:make_list("le 1.7.13"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Suite");
}
