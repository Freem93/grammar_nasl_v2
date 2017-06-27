#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200901-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35347);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2015/05/29 04:35:54 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-4194");
  script_bugtraq_id(30131);
  script_osvdb_id(46776, 46777, 46786, 46836, 46837, 46916, 47232, 47233, 47510, 47546, 47588, 47660, 47916, 47926, 47927, 48186, 48244, 48245, 48256);
  script_xref(name:"GLSA", value:"200901-03");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"GLSA-200901-03 : pdnsd: Denial of Service and cache poisoning");
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
"The remote host is affected by the vulnerability described in GLSA-200901-03
(pdnsd: Denial of Service and cache poisoning)

    Two issues have been reported in pdnsd:
    The p_exec_query() function in src/dns_query.c does not properly handle
    many entries in the answer section of a DNS reply, related to a
    'dangling pointer bug' (CVE-2008-4194).
    The default value for query_port_start was set to 0, disabling UDP
    source port randomization for outgoing queries (CVE-2008-1447).
  
Impact :

    An attacker could exploit the second weakness to poison the cache of
    pdnsd and thus spoof DNS traffic, which could e.g. lead to the
    redirection of web or mail traffic to malicious sites. The first issue
    can be exploited by enticing pdnsd to send a query to a malicious DNS
    server, or using the port randomization weakness, and might lead to a
    Denial of Service.
  
Workaround :

    Port randomization can be enabled by setting the 'query_port_start'
    option to 1024 which would resolve the CVE-2008-1447 issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200901-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All pdnsd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/pdnsd-1.2.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pdnsd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-dns/pdnsd", unaffected:make_list("ge 1.2.7"), vulnerable:make_list("lt 1.2.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdnsd");
}
