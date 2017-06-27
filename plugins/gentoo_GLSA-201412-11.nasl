#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(79964);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2007-0720", "CVE-2007-1536", "CVE-2007-2026", "CVE-2007-2445", "CVE-2007-2741", "CVE-2007-3108", "CVE-2007-4995", "CVE-2007-5116", "CVE-2007-5135", "CVE-2007-5266", "CVE-2007-5268", "CVE-2007-5269", "CVE-2007-5849", "CVE-2010-1205", "CVE-2013-0338", "CVE-2013-0339", "CVE-2013-1664", "CVE-2013-1969", "CVE-2013-2877", "CVE-2014-0160");
  script_bugtraq_id(41174, 58180, 58892, 59000, 59265, 61050, 66690);
  script_xref(name:"GLSA", value:"201412-11");

  script_name(english:"GLSA-201412-11 : AMD64 x86 emulation base libraries: Multiple vulnerabilities (Heartbleed)");
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
"The remote host is affected by the vulnerability described in GLSA-201412-11
(AMD64 x86 emulation base libraries: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in AMD64 x86 emulation
      base libraries. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    A context-dependent attacker may be able to execute arbitrary code,
      cause a Denial of Service condition, or obtain sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users of the AMD64 x86 emulation base libraries should upgrade to
      the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/emul-linux-x86-baselibs-20140406-r1'
    NOTE: One or more of the issues described in this advisory have been
      fixed in previous updates. They are included in this advisory for the
      sake of completeness. It is likely that your system is already no longer
      affected by them."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-baselibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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

if (qpkg_check(package:"app-emulation/emul-linux-x86-baselibs", unaffected:make_list("ge 20140406-r1"), vulnerable:make_list("lt 20140406-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "AMD64 x86 emulation base libraries");
}
