#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201409-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(77886);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/14 04:39:16 $");

  script_cve_id("CVE-2014-7169");
  script_bugtraq_id(70137);
  script_xref(name:"GLSA", value:"201409-10");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"GLSA-201409-10 : Bash: Code Injection (Updated fix for GLSA 201409-09)");
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
"The remote host is affected by the vulnerability described in GLSA-201409-10
(Bash: Code Injection (Updated fix for GLSA 201409-09))

    Stephane Chazelas reported that Bash incorrectly handles function
      definitions, allowing attackers to inject arbitrary code (CVE-2014-6271).
      Gentoo Linux informed about this issue in GLSA 201409-09.
    Tavis Ormandy reported that the patch for CVE-2014-6271 was incomplete.
      As such, this GLSA supersedes GLSA 201409-09.
  
Impact :

    A remote attacker could exploit this vulnerability to execute arbitrary
      commands even in restricted environments.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201409-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Bash 3.1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-3.1_p18-r1:3.1'
    All Bash 3.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-3.2_p52-r1:3.2'
    All Bash 4.0 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.0_p39-r1:4.0'
    All Bash 4.1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.1_p12-r1:4.1'
    All Bash 4.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.2_p48-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-shells/bash", unaffected:make_list("rge 3.1_p18-r1", "rge 3.2_p52-r1", "rge 4.0_p39-r1", "rge 4.1_p12-r1", "ge 4.2_p48-r1"), vulnerable:make_list("lt 4.2_p48-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Bash");
}
