#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200511-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20197);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_osvdb_id(19914);
  script_xref(name:"GLSA", value:"200511-10");

  script_name(english:"GLSA-200511-10 : RAR: Format string and buffer overflow vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200511-10
(RAR: Format string and buffer overflow vulnerabilities)

    Tan Chew Keong reported about two vulnerabilities found in RAR:
    A format string error exists when displaying a diagnostic
    error message that informs the user of an invalid filename in an
    UUE/XXE encoded file.
    Some boundary errors in the processing
    of malicious ACE archives can be exploited to cause a buffer
    overflow.
  
Impact :

    A remote attacker could exploit these vulnerabilities by enticing
    a user to:
    decode a specially crafted UUE/XXE file,
    or
    extract a malicious ACE archive containing a file with an
    overly long filename.
    When the user performs these
    actions, the arbitrary code of the attacker's choice will be executed.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rarlabs.com/rarnew.htm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2005-53/advisory/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200511-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All RAR users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-arch/rar-3.5.1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/11");
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

if (qpkg_check(package:"app-arch/rar", unaffected:make_list("ge 3.5.1"), vulnerable:make_list("lt 3.5.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "RAR");
}
