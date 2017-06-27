#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201410-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(78060);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/13 04:40:05 $");

  script_cve_id("CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7186", "CVE-2014-7187");
  script_bugtraq_id(70152, 70154, 70165, 70166);
  script_osvdb_id(112096, 112097, 112158, 112169);
  script_xref(name:"GLSA", value:"201410-01");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"GLSA-201410-01 : Bash: Multiple vulnerabilities (Shellshock)");
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
"The remote host is affected by the vulnerability described in GLSA-201410-01
(Bash: Multiple vulnerabilities)

    Florian Weimer, Todd Sabin, Michal Zalewski et al. discovered further
      parsing flaws in Bash. The unaffected Gentoo packages listed in this GLSA
      contain the official patches to fix the issues tracked as CVE-2014-6277,
      CVE-2014-7186, and CVE-2014-7187. Furthermore, the official patch known
      as &ldquo;function prefix patch&rdquo; is included which prevents the
      exploitation of CVE-2014-6278.
  
Impact :

    A remote attacker could exploit these vulnerabilities to execute
      arbitrary commands or cause a Denial of Service condition via various
      vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201410-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Bash 3.1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-3.1_p22:3.1'
    All Bash 3.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-3.2_p56:3.2'
    All Bash 4.0 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.0_p43:4.0'
    All Bash 4.1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.1_p16:4.1'
    All Bash 4.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-shells/bash-4.2_p52'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/04");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-shells/bash", unaffected:make_list("rge 3.1_p22", "rge 3.2_p56", "rge 4.0_p43", "rge 4.1_p16", "ge 4.2_p52"), vulnerable:make_list("lt 4.2_p52"))) flag++;

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
