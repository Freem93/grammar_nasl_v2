#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200708-17.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(26040);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 14:04:23 $");

  script_cve_id("CVE-2007-3142", "CVE-2007-3819", "CVE-2007-3929", "CVE-2007-4367");
  script_bugtraq_id(24352, 24917, 24970);
  script_osvdb_id(38122, 38123, 43463, 45946);
  script_xref(name:"GLSA", value:"200708-17");

  script_name(english:"GLSA-200708-17 : Opera: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200708-17
(Opera: Multiple vulnerabilities)

    An error known as 'a virtual function call on an invalid pointer' has
    been discovered in the JavaScript engine (CVE-2007-4367). Furthermore,
    iDefense Labs reported that an already-freed pointer may be still used
    under unspecified circumstances in the BitTorrent support
    (CVE-2007-3929). At last, minor other errors have been discovered,
    relative to memory read protection (Opera Advisory 861) and URI
    displays (CVE-2007-3142, CVE-2007-3819).
  
Impact :

    A remote attacker could trigger the BitTorrent vulnerability by
    enticing a user into starting a malicious BitTorrent download, and
    execute arbitrary code through unspecified vectors. Additionally, a
    specially crafted JavaScript may trigger the 'virtual function'
    vulnerability. The JavaScript engine can also access previously freed
    but uncleaned memory. Finally, a user can be fooled with a too long
    HTTP server name that does not fit the dialog box, or a URI containing
    whitespaces.
  
Workaround :

    There is no known workaround at this time for all these
    vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/search/view/861/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200708-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/opera-9.23'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 9.23"), vulnerable:make_list("lt 9.23"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Opera");
}
