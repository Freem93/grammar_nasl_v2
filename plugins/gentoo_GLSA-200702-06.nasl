#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200702-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24367);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2007-0493", "CVE-2007-0494");
  script_bugtraq_id(22229, 22231);
  script_osvdb_id(31922, 31923);
  script_xref(name:"GLSA", value:"200702-06");

  script_name(english:"GLSA-200702-06 : BIND: Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-200702-06
(BIND: Denial of Service)

    An unspecified improper usage of an already freed context has been
    reported. Additionally, an assertion error could be triggered in the
    DNSSEC validation of some responses to type ANY queries with multiple
    RRsets.
  
Impact :

    A remote attacker could crash the server through unspecified vectors
    or, if DNSSEC validation is enabled, by sending certain crafted ANY
    queries.
  
Workaround :

    There is no known workaround at this time for the first issue. The
    DNSSEC validation Denial of Service can be prevented by disabling
    DNSSEC validation until the upgrade to a fixed version. Note that
    DNSSEC validation is disabled on a default configuration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200702-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ISC BIND 9.3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/bind-9.3.4'
    All ISC BIND 9.2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/bind-9.2.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/25");
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

if (qpkg_check(package:"net-dns/bind", unaffected:make_list("ge 9.3.4", "rge 9.2.8"), vulnerable:make_list("lt 9.3.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BIND");
}
