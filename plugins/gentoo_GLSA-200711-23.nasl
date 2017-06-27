#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-23.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(28262);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2004-0813", "CVE-2006-3619", "CVE-2006-4146", "CVE-2006-4600", "CVE-2007-0061", "CVE-2007-0062", "CVE-2007-0063", "CVE-2007-1716", "CVE-2007-4496", "CVE-2007-4497", "CVE-2007-5617");
  script_osvdb_id(10352, 25848, 27380, 28318, 28464, 28549, 29260, 29261, 29262, 31922, 31923, 34699, 34700, 34731, 34732, 34733, 34975, 36595, 36596, 36597, 37271, 40092, 40093, 40094, 40096);
  script_xref(name:"GLSA", value:"200711-23");

  script_name(english:"GLSA-200711-23 : VMware Workstation and Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200711-23
(VMware Workstation and Player: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in several VMware
    products. Neel Mehta and Ryan Smith (IBM ISS X-Force) discovered that
    the DHCP server contains an integer overflow vulnerability
    (CVE-2007-0062), an integer underflow vulnerability (CVE-2007-0063) and
    another error when handling malformed packets (CVE-2007-0061), leading
    to stack-based buffer overflows or stack corruption. Rafal Wojtczvk
    (McAfee) discovered two unspecified errors that allow authenticated
    users with administrative or login privileges on a guest operating
    system to corrupt memory or cause a Denial of Service (CVE-2007-4496,
    CVE-2007-4497). Another unspecified vulnerability related to untrusted
    virtual machine images was discovered (CVE-2007-5617).
    VMware products also shipped code copies of software with several
    vulnerabilities: Samba (GLSA-200705-15), BIND (GLSA-200702-06), MIT
    Kerberos 5 (GLSA-200707-11), Vixie Cron (GLSA-200704-11), shadow
    (GLSA-200606-02), OpenLDAP (CVE-2006-4600), PAM (CVE-2004-0813,
    CVE-2007-1716), GCC (CVE-2006-3619) and GDB (CVE-2006-4146).
  
Impact :

    Remote attackers within a guest system could possibly exploit these
    vulnerabilities to execute code on the host system with elevated
    privileges or to cause a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200606-02.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200702-06.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200704-11.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200705-15.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200707-11.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2007/000001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VMware Workstation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/vmware-workstation-5.5.5.56455'
    All VMware Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/vmware-player-1.0.5.56455'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vmware-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vmware-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulation/vmware-player", unaffected:make_list("ge 1.0.5.56455"), vulnerable:make_list("lt 1.0.5.56455", "eq 2.0.0.45731"))) flag++;
if (qpkg_check(package:"app-emulation/vmware-workstation", unaffected:make_list("ge 5.5.5.56455"), vulnerable:make_list("lt 5.5.5.56455", "eq 6.0.0.45731"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VMware Workstation and Player");
}
