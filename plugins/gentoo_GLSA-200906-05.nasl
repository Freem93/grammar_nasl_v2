#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200906-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39580);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685", "CVE-2008-5285", "CVE-2008-6472", "CVE-2009-0599", "CVE-2009-0600", "CVE-2009-0601", "CVE-2009-1210", "CVE-2009-1266", "CVE-2009-1268", "CVE-2009-1269", "CVE-2009-1829");
  script_bugtraq_id(31838, 32422, 34291, 34457, 35081);
  script_osvdb_id(49340, 49341, 49342, 49343, 49344, 49345, 50069, 51815, 51987, 52157, 52719, 52996, 53669, 53670, 53903, 54629);
  script_xref(name:"GLSA", value:"200906-05");

  script_name(english:"GLSA-200906-05 : Wireshark: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200906-05
(Wireshark: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Wireshark:
    David Maciejak discovered a vulnerability in packet-usb.c in the USB
    dissector via a malformed USB Request Block (URB) (CVE-2008-4680).
    Florent Drouin and David Maciejak reported an unspecified vulnerability
    in the Bluetooth RFCOMM dissector (CVE-2008-4681).
    A malformed Tamos CommView capture file (aka .ncf file) with an
    'unknown/unexpected packet type' triggers a failed assertion in wtap.c
    (CVE-2008-4682).
    An unchecked packet length parameter in the dissect_btacl() function in
    packet-bthci_acl.c in the Bluetooth ACL dissector causes an erroneous
    tvb_memcpy() call (CVE-2008-4683).
    A vulnerability where packet-frame does not properly handle exceptions
    thrown by post dissectors caused by a certain series of packets
    (CVE-2008-4684).
    Mike Davies reported a use-after-free vulnerability in the
    dissect_q931_cause_ie() function in packet-q931.c in the Q.931
    dissector via certain packets that trigger an exception
    (CVE-2008-4685).
    The Security Vulnerability Research Team of Bkis reported that the SMTP
    dissector could consume excessive amounts of CPU and memory
    (CVE-2008-5285).
    The vendor reported that the WLCCP dissector could go into an infinite
    loop (CVE-2008-6472).
    babi discovered a buffer overflow in wiretap/netscreen.c via a
    malformed NetScreen snoop file (CVE-2009-0599).
    A specially crafted Tektronix K12 text capture file can cause an
    application crash (CVE-2009-0600).
    A format string vulnerability via format string specifiers in the HOME
    environment variable (CVE-2009-0601).
    THCX Labs reported a format string vulnerability in the
    PROFINET/DCP (PN-DCP) dissector via a PN-DCP packet with format string
    specifiers in the station name (CVE-2009-1210).
    An unspecified vulnerability with unknown impact and attack vectors
    (CVE-2009-1266).
    Marty Adkins and Chris Maynard discovered a parsing error in the
    dissector for the Check Point High-Availability Protocol (CPHAP)
    (CVE-2009-1268).
    Magnus Homann discovered a parsing error when loading a Tektronix .rf5
    file (CVE-2009-1269).
    The vendor reported that the PCNFSD dissector could crash
    (CVE-2009-1829).
  
Impact :

    A remote attacker could exploit these vulnerabilities by sending
    specially crafted packets on a network being monitored by Wireshark or
    by enticing a user to read a malformed packet trace file which can
    trigger a Denial of Service (application crash or excessive CPU and
    memory usage) and possibly allow for the execution of arbitrary code
    with the privileges of the user running Wireshark.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200906-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-1.0.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 134, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/01");
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

if (qpkg_check(package:"net-analyzer/wireshark", unaffected:make_list("ge 1.0.8"), vulnerable:make_list("lt 1.0.8"))) flag++;

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
