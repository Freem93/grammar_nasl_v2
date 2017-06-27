#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201502-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(81227);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/13 14:33:57 $");

  script_cve_id("CVE-2013-6451", "CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6454", "CVE-2013-6472", "CVE-2014-1610", "CVE-2014-2242", "CVE-2014-2243", "CVE-2014-2244", "CVE-2014-2665", "CVE-2014-2853", "CVE-2014-5241", "CVE-2014-5242", "CVE-2014-5243", "CVE-2014-7199", "CVE-2014-7295", "CVE-2014-9276", "CVE-2014-9277", "CVE-2014-9475", "CVE-2014-9476", "CVE-2014-9477", "CVE-2014-9478", "CVE-2014-9479", "CVE-2014-9480", "CVE-2014-9481", "CVE-2014-9487", "CVE-2014-9507");
  script_xref(name:"GLSA", value:"201502-04");

  script_name(english:"GLSA-201502-04 : MediaWiki: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201502-04
(MediaWiki: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MediaWiki. Please
      review the CVE identifiers and MediaWiki announcement referenced below
      for details.
  
Impact :

    A remote attacker may be able to execute arbitrary code with the
      privileges of the process, create a Denial of Service condition, obtain
      sensitive information, bypass security restrictions, and inject arbitrary
      web script or HTML.
  
Workaround :

    There is no known workaround at this time."
  );
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-June/000155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ef35312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201502-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MediaWiki 1.23 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.23.8'
    All MediaWiki 1.22 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.22.15'
    All MediaWiki 1.19 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.19.23'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MediaWiki thumb.php page Parameter Remote Shell Command Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MediaWiki Thumb.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/mediawiki", unaffected:make_list("ge 1.23.8", "rge 1.22.15", "rge 1.19.23"), vulnerable:make_list("lt 1.23.8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MediaWiki");
}
