#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201207-10.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59902);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-3553", "CVE-2010-0302", "CVE-2010-0393", "CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748", "CVE-2010-2431", "CVE-2010-2432", "CVE-2010-2941", "CVE-2011-3170");
  script_bugtraq_id(37048, 38510, 38524, 40889, 40897, 40943, 41126, 41131, 44530, 49323);
  script_xref(name:"GLSA", value:"201207-10");

  script_name(english:"GLSA-201207-10 : CUPS: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201207-10
(CUPS: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in CUPS. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A remote attacker may be able to execute arbitrary code using specially
      crafted streams, IPP requests or files, or cause a Denial of Service
      (daemon crash or hang). A local attacker may be able to gain escalated
      privileges or overwrite arbitrary files. Furthermore, a remote attacker
      may be able to obtain sensitive information from the CUPS process or
      hijack a CUPS administrator authentication request.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201207-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CUPS users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-print/cups-1.4.8-r1'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since September 03, 2011. It is likely that your system is
      already no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-print/cups", unaffected:make_list("ge 1.4.8-r1"), vulnerable:make_list("lt 1.4.8-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CUPS");
}
