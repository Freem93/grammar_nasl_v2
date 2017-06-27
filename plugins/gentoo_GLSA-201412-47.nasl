#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-47.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(80268);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/13 14:33:57 $");

  script_cve_id("CVE-2011-2193", "CVE-2011-2907", "CVE-2011-4925", "CVE-2013-4319", "CVE-2013-4495", "CVE-2014-0749");
  script_bugtraq_id(48374, 49119, 51224, 62273, 63722, 67420);
  script_xref(name:"GLSA", value:"201412-47");

  script_name(english:"GLSA-201412-47 : TORQUE Resource Manager: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201412-47
(TORQUE Resource Manager: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in TORQUE Resource
      Manager. Please review the CVE identifiers referenced below for details.
  
Impact :

    A context-dependent attacker may be able to gain escalated privileges,
      execute arbitrary code, or bypass security restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-47"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All TORQUE Resource Manager 4.x users should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-cluster/torque-4.1.7'
    All TORQUE Resource Manager 2.x users should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-cluster/torque-2.5.13'
    NOTE: One or more of the issues described in this advisory have been
      fixed in previous updates. They are included in this advisory for the
      sake of completeness. It is likely that your system is already no longer
      affected by them."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:torque");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/29");
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

if (qpkg_check(package:"sys-cluster/torque", unaffected:make_list("ge 4.1.7", "rge 2.5.13"), vulnerable:make_list("lt 4.1.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "TORQUE Resource Manager");
}
