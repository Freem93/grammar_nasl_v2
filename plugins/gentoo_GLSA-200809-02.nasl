#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200809-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(34091);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/04/29 04:40:48 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-3350");
  script_osvdb_id(46776, 46777, 46786, 46836, 46837, 46916, 47232, 47233, 47509, 47510, 47546, 47588, 47660, 49083, 49084);
  script_xref(name:"GLSA", value:"200809-02");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"GLSA-200809-02 : dnsmasq: Denial of Service and DNS spoofing");
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
"The remote host is affected by the vulnerability described in GLSA-200809-02
(dnsmasq: Denial of Service and DNS spoofing)

    Dan Kaminsky of IOActive reported that dnsmasq does not randomize UDP
    source ports when forwarding DNS queries to a recursing DNS server
    (CVE-2008-1447).
    Carlos Carvalho reported that dnsmasq in the 2.43 version does not
    properly handle clients sending inform or renewal queries for unknown
    DHCP leases, leading to a crash (CVE-2008-3350).
  
Impact :

    A remote attacker could send spoofed DNS response traffic to dnsmasq,
    possibly involving generating queries via multiple vectors, and spoof
    DNS replies, which could e.g. lead to the redirection of web or mail
    traffic to malicious sites. Furthermore, an attacker could generate
    invalid DHCP traffic and cause a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200809-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All dnsmasq users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/dnsmasq-2.45'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/05");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-dns/dnsmasq", unaffected:make_list("ge 2.45"), vulnerable:make_list("lt 2.45"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq");
}
