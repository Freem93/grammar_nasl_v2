#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201006-13.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(46793);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2008-1066", "CVE-2008-4810", "CVE-2008-4811", "CVE-2009-1669");
  script_bugtraq_id(28105, 31862, 34918);
  script_osvdb_id(43064, 49943, 54380);
  script_xref(name:"GLSA", value:"201006-13");

  script_name(english:"GLSA-201006-13 : Smarty: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201006-13
(Smarty: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Smarty:
    The vendor reported that the modifier.regex_replace.php plug-in
    contains an input sanitation flaw related to the ASCII NUL character
    (CVE-2008-1066).
    The vendor reported that the
    _expand_quoted_text() function in libs/Smarty_Compiler.class.php
    contains an input sanitation flaw via multiple vectors (CVE-2008-4810,
    CVE-2008-4811).
    Nine:Situations:Group::bookoo reported that
    the smarty_function_math() function in libs/plugins/function.math.php
    contains input sanitation flaw (CVE-2009-1669).
  
Impact :

    These issues might allow a remote attacker to execute arbitrary PHP
    code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201006-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Smarty users should upgrade to an unaffected version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/smarty-2.6.23'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
    available since June 2, 2009. It is likely that your system is already
    no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:smarty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-php/smarty", unaffected:make_list("ge 2.6.23"), vulnerable:make_list("lt 2.6.23"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Smarty");
}
