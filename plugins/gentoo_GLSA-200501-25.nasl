#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-25.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16416);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0194");
  script_osvdb_id(12886, 12887);
  script_xref(name:"GLSA", value:"200501-25");

  script_name(english:"GLSA-200501-25 : Squid: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200501-25
(Squid: Multiple vulnerabilities)

    Squid contains a vulnerability in the gopherToHTML function
    (CAN-2005-0094) and incorrectly checks the 'number of caches' field
    when parsing WCCP_I_SEE_YOU messages (CAN-2005-0095). Furthermore the
    NTLM code contains two errors. One is a memory leak in the
    fakeauth_auth helper (CAN-2005-0096) and the other is a NULL pointer
    dereferencing error (CAN-2005-0097). Finally Squid also contains an
    error in the ACL parsing code (CAN-2005-0194).
  
Impact :

    With the WCCP issue an attacker could cause denial of service by
    sending a specially crafted UDP packet. With the Gopher issue an
    attacker might be able to execute arbitrary code by enticing a user to
    connect to a malicious Gopher server. The NTLM issues could lead to
    denial of service by memory consumption or by crashing Squid. The ACL
    issue could lead to ACL bypass.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/13825/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/13789/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-proxy/squid-2.5.7-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-proxy/squid", unaffected:make_list("ge 2.5.7-r2"), vulnerable:make_list("lt 2.5.7-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Squid");
}
