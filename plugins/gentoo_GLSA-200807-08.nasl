#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200807-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33494);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/04/29 04:40:48 $");

  script_cve_id("CVE-2008-1447");
  script_osvdb_id(46776, 47232, 47916, 47926, 47927, 48245);
  script_xref(name:"GLSA", value:"200807-08");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"GLSA-200807-08 : BIND: Cache poisoning");
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
"The remote host is affected by the vulnerability described in GLSA-200807-08
(BIND: Cache poisoning)

    Dan Kaminsky of IOActive has reported a weakness in the DNS protocol
    related to insufficient randomness of DNS transaction IDs and query
    source ports.
  
Impact :

    An attacker could exploit this weakness to poison the cache of a
    recursive resolver and thus spoof DNS traffic, which could e.g. lead to
    the redirection of web or mail traffic to malicious sites.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200807-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All BIND users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/bind-9.4.2_p1'
    Note: In order to utilize the query port randomization to mitigate the
    weakness, you need to make sure that your network setup allows the DNS
    server to use random source ports for query and that you have not set a
    fixed query port via the 'query-source port' directive in the BIND
    configuration."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
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

if (qpkg_check(package:"net-dns/bind", unaffected:make_list("ge 9.4.2_p1"), vulnerable:make_list("lt 9.4.2_p1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BIND");
}
