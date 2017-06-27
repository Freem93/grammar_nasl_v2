#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200911-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(42915);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-2560", "CVE-2009-3241", "CVE-2009-3242", "CVE-2009-3243", "CVE-2009-3549", "CVE-2009-3550", "CVE-2009-3551", "CVE-2009-3829");
  script_bugtraq_id(35748, 36408, 36591, 36846);
  script_osvdb_id(56019, 56020, 56021, 58157, 58237, 58238, 59458, 59459, 59460, 59461, 59478);
  script_xref(name:"GLSA", value:"200911-05");

  script_name(english:"GLSA-200911-05 : Wireshark: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200911-05
(Wireshark: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Wireshark:
    Ryan Giobbi reported an integer overflow in wiretap/erf.c
    (CVE-2009-3829).
    The vendor reported multiple unspecified
    vulnerabilities in the Bluetooth L2CAP, RADIUS, and MIOP dissectors
    (CVE-2009-2560), in the OpcUa dissector (CVE-2009-3241), in packet.c in
    the GSM A RR dissector (CVE-2009-3242), in the TLS dissector
    (CVE-2009-3243), in the Paltalk dissector (CVE-2009-3549), in the
    DCERPC/NT dissector (CVE-2009-3550), and in the
    dissect_negprot_response() function in packet-smb.c in the SMB
    dissector (CVE-2009-3551).
  
Impact :

    A remote attacker could entice a user to open a specially crafted 'erf'
    file using Wireshark, possibly resulting in the execution of arbitrary
    code with the privileges of the user running the application. A remote
    attacker could furthermore send specially crafted packets on a network
    being monitored by Wireshark or entice a user to open a malformed
    packet trace file using Wireshark, possibly resulting in a Denial of
    Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200911-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-1.2.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-analyzer/wireshark", unaffected:make_list("ge 1.2.3"), vulnerable:make_list("lt 1.2.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Wireshark");
}
