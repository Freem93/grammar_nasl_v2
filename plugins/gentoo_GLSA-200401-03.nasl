#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200401-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14443);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200401-03");

  script_name(english:"GLSA-200401-03 : Apache mod_python Denial of Service vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200401-03
(Apache mod_python Denial of Service vulnerability)

    The Apache Foundation has reported that mod_python may be prone to
    Denial of Service attacks when handling a malformed
    query. Mod_python 2.7.9 was released to fix the vulnerability,
    however, because the vulnerability has not been fully fixed,
    version 2.7.10 has been released.
    Users of mod_python 3.0.4 are not affected by this vulnerability.
  
Impact :

    Although there are no known public exploits known for this
    exploit, users are recommended to upgrade mod_python to ensure the
    security of their infrastructure.
  
Workaround :

    Mod_python 2.7.10 has been released to solve this issue; there is
    no immediate workaround."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.modpython.org/pipermail/mod_python/2004-January/014879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200401-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users using mod_python 2.7.9 or below are recommended to
    update their mod_python installation:
    $> emerge sync
    $> emerge -pv '>=www-apache/mod_python-2.7.10'
    $> emerge '>=www-apache/mod_python-2.7.10'
    $> /etc/init.d/apache restart"
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/27");
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

if (qpkg_check(package:"www-apache/mod_python", unaffected:make_list("ge 2.7.10"), vulnerable:make_list("lt 2.7.10"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "www-apache/mod_python");
}
