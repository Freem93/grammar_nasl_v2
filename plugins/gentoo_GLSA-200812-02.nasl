#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200812-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35019);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:11:58 $");

  script_cve_id("CVE-2008-3863", "CVE-2008-4306");
  script_bugtraq_id(31858);
  script_osvdb_id(49224, 49569);
  script_xref(name:"GLSA", value:"200812-02");

  script_name(english:"GLSA-200812-02 : enscript: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200812-02
(enscript: User-assisted execution of arbitrary code)

    Two stack-based buffer overflows in the read_special_escape() function
    in src/psgen.c have been reported. Ulf Harnhammar of Secunia Research
    discovered a vulnerability related to the 'setfilename' command
    (CVE-2008-3863), and Kees Cook of Ubuntu discovered a vulnerability
    related to the 'font' escape sequence (CVE-2008-4306).
  
Impact :

    An attacker could entice a user or automated system to process
    specially crafted input with the special escapes processing enabled
    using the '-e' option, possibly resulting in the execution of arbitrary
    code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200812-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All enscript users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/enscript-1.6.4-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:enscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/enscript", unaffected:make_list("ge 1.6.4-r4"), vulnerable:make_list("lt 1.6.4-r4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "enscript");
}
