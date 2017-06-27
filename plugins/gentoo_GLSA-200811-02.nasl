#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200811-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(34733);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-3600", "CVE-2008-3662", "CVE-2008-4129", "CVE-2008-4130");
  script_bugtraq_id(31231);
  script_osvdb_id(47429, 47650, 47651, 47652, 47653, 47654, 48213, 48214, 49127);
  script_xref(name:"GLSA", value:"200811-02");

  script_name(english:"GLSA-200811-02 : Gallery: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200811-02
(Gallery: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Gallery 1 and 2:
    Digital Security Research Group reported a directory traversal
    vulnerability in contrib/phpBB2/modules.php in Gallery 1, when
    register_globals is enabled (CVE-2008-3600).
    Hanno Boeck reported that Gallery 1 and 2 did not set the secure flag
    for the session cookie in an HTTPS session (CVE-2008-3662).
    Alex Ustinov reported that Gallery 1 and 2 does not properly handle ZIP
    archives containing symbolic links (CVE-2008-4129).
    The vendor reported a Cross-Site Scripting vulnerability in Gallery 2
    (CVE-2008-4130).
  
Impact :

    Remote attackers could send specially crafted requests to a server
    running Gallery, allowing for the execution of arbitrary code when
    register_globals is enabled, or read arbitrary files via directory
    traversals otherwise. Attackers could also entice users to visit
    crafted links allowing for theft of login credentials.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200811-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Gallery 2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/gallery-2.2.6'
    All Gallery 1 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/gallery-1.5.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gallery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/11");
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

if (qpkg_check(package:"www-apps/gallery", unaffected:make_list("ge 2.2.6", "rge 1.5.9", "rge 1.5.10"), vulnerable:make_list("lt 2.2.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gallery");
}
