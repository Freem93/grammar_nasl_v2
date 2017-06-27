#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14468);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2003-0989");
  script_xref(name:"GLSA", value:"200404-03");

  script_name(english:"GLSA-200404-03 : Tcpdump Vulnerabilities in ISAKMP Parsing");
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
"The remote host is affected by the vulnerability described in GLSA-200404-03
(Tcpdump Vulnerabilities in ISAKMP Parsing)

    There are two specific vulnerabilities in tcpdump, outlined in [ reference
    1 ]. In the first scenario, an attacker may send a specially crafted ISAKMP
    Delete packet which causes tcpdump to read past the end of its buffer. In
    the second scenario, an attacker may send an ISAKMP packet with the wrong
    payload length, again causing tcpdump to read past the end of a buffer.
  
Impact :

    Remote attackers could potentially cause tcpdump to crash or execute
    arbitrary code as the 'pcap' user.
  
Workaround :

    There is no known workaround at this time. All tcpdump users are encouraged
    to upgrade to the latest available version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rapid7.com/advisories/R7-0017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All tcpdump users should upgrade to the latest available version.
    ADDITIONALLY, the net-libs/libpcap package should be upgraded.
    # emerge sync
    # emerge -pv '>=net-libs/libpcap-0.8.3-r1' '>=net-analyzer/tcpdump-3.8.3-r1'
    # emerge '>=net-libs/libpcap-0.8.3-r1' '>=net-analyzer/tcpdump-3.8.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-libs/libpcap", unaffected:make_list("ge 0.8.3-r1"), vulnerable:make_list("le 0.8.1-r1"))) flag++;
if (qpkg_check(package:"net-analyzer/tcpdump", unaffected:make_list("ge 3.8.3-r1"), vulnerable:make_list("le 3.8.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-libs/libpcap / net-analyzer/tcpdump");
}
