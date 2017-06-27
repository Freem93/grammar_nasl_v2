#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201209-25.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(62383);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/14 14:40:46 $");

  script_cve_id("CVE-2007-5269", "CVE-2007-5503", "CVE-2007-5671", "CVE-2008-0967", "CVE-2008-1340", "CVE-2008-1361", "CVE-2008-1362", "CVE-2008-1363", "CVE-2008-1364", "CVE-2008-1392", "CVE-2008-1447", "CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2008-2098", "CVE-2008-2100", "CVE-2008-2101", "CVE-2008-4915", "CVE-2008-4916", "CVE-2008-4917", "CVE-2009-0040", "CVE-2009-0909", "CVE-2009-0910", "CVE-2009-1244", "CVE-2009-2267", "CVE-2009-3707", "CVE-2009-3732", "CVE-2009-3733", "CVE-2009-4811", "CVE-2010-1137", "CVE-2010-1138", "CVE-2010-1139", "CVE-2010-1140", "CVE-2010-1141", "CVE-2010-1142", "CVE-2010-1143", "CVE-2011-3868");
  script_bugtraq_id(25956, 26650, 28276, 28289, 29444, 29552, 29557, 29637, 29639, 29640, 29641, 30131, 30937, 32168, 32597, 33827, 33990, 34373, 34471, 36630, 36841, 36842, 39104, 39392, 39394, 39395, 39396, 39397, 39407, 39949, 49942);
  script_xref(name:"GLSA", value:"201209-25");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"GLSA-201209-25 : VMware Player, Server, Workstation: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201209-25
(VMware Player, Server, Workstation: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in VMware Player, Server,
      and Workstation. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    Local users may be able to gain escalated privileges, cause a Denial of
      Service, or gain sensitive information.
    A remote attacker could entice a user to open a specially crafted file,
      possibly resulting in the remote execution of arbitrary code, or a Denial
      of Service. Remote attackers also may be able to spoof DNS traffic, read
      arbitrary files, or inject arbitrary web script to the VMware Server
      Console.
    Furthermore, guest OS users may be able to execute arbitrary code on the
      host OS, gain escalated privileges on the guest OS, or cause a Denial of
      Service (crash the host OS).
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201209-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Gentoo discontinued support for VMware Player. We recommend that users
      unmerge VMware Player:
      # emerge --unmerge 'app-emulation/vmware-player'
    NOTE: Users could upgrade to
      &ldquo;>=app-emulation/vmware-player-3.1.5&rdquo;, however these packages are
      not currently stable.
    Gentoo discontinued support for VMware Workstation. We recommend that
      users unmerge VMware Workstation:
      # emerge --unmerge 'app-emulation/vmware-workstation'
    NOTE: Users could upgrade to
      &ldquo;>=app-emulation/vmware-workstation-7.1.5&rdquo;, however these packages
      are not currently stable.
    Gentoo discontinued support for VMware Server. We recommend that users
      unmerge VMware Server:
      # emerge --unmerge 'app-emulation/vmware-server'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-757");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Vmware Server File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(16, 20, 22, 94, 119, 134, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vmware-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vmware-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vmware-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/01");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (qpkg_check(package:"app-emulation/vmware-player", unaffected:make_list(), vulnerable:make_list("le 2.5.5.328052"))) flag++;
if (qpkg_check(package:"app-emulation/vmware-workstation", unaffected:make_list(), vulnerable:make_list("le 6.5.5.328052"))) flag++;
if (qpkg_check(package:"app-emulation/vmware-server", unaffected:make_list(), vulnerable:make_list("le 1.0.9.156507"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VMware Player / Server / Workstation");
}
