#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59631);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-1234", "CVE-2009-2059", "CVE-2009-2063", "CVE-2009-2067", "CVE-2009-2070", "CVE-2009-3013", "CVE-2009-3044", "CVE-2009-3045", "CVE-2009-3046", "CVE-2009-3047", "CVE-2009-3048", "CVE-2009-3049", "CVE-2009-3831", "CVE-2009-4071", "CVE-2009-4072", "CVE-2010-0653", "CVE-2010-1349", "CVE-2010-1989", "CVE-2010-1993", "CVE-2010-2121", "CVE-2010-2421", "CVE-2010-2455", "CVE-2010-2576", "CVE-2010-2658", "CVE-2010-2659", "CVE-2010-2660", "CVE-2010-2661", "CVE-2010-2662", "CVE-2010-2663", "CVE-2010-2664", "CVE-2010-2665", "CVE-2010-3019", "CVE-2010-3020", "CVE-2010-3021", "CVE-2010-4579", "CVE-2010-4580", "CVE-2010-4581", "CVE-2010-4582", "CVE-2010-4583", "CVE-2010-4584", "CVE-2010-4585", "CVE-2010-4586", "CVE-2011-0681", "CVE-2011-0682", "CVE-2011-0683", "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0686", "CVE-2011-0687", "CVE-2011-1337", "CVE-2011-1824", "CVE-2011-2609", "CVE-2011-2610", "CVE-2011-2611", "CVE-2011-2612", "CVE-2011-2613", "CVE-2011-2614", "CVE-2011-2615", "CVE-2011-2616", "CVE-2011-2617", "CVE-2011-2618", "CVE-2011-2619", "CVE-2011-2620", "CVE-2011-2621", "CVE-2011-2622", "CVE-2011-2623", "CVE-2011-2624", "CVE-2011-2625", "CVE-2011-2626", "CVE-2011-2627", "CVE-2011-2628", "CVE-2011-2629", "CVE-2011-2630", "CVE-2011-2631", "CVE-2011-2632", "CVE-2011-2633", "CVE-2011-2634", "CVE-2011-2635", "CVE-2011-2636", "CVE-2011-2637", "CVE-2011-2638", "CVE-2011-2639", "CVE-2011-2640", "CVE-2011-2641", "CVE-2011-3388", "CVE-2011-4065", "CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683", "CVE-2012-1924", "CVE-2012-1925", "CVE-2012-1926", "CVE-2012-1927", "CVE-2012-1928", "CVE-2012-1930", "CVE-2012-1931", "CVE-2012-3555", "CVE-2012-3556", "CVE-2012-3557", "CVE-2012-3558", "CVE-2012-3560", "CVE-2012-3561");
  script_xref(name:"GLSA", value:"201206-03");

  script_name(english:"GLSA-201206-03 : Opera: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-03
(Opera: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Opera. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted web
      page, possibly resulting in execution of arbitrary code with the
      privileges of the process or a Denial of Service condition. A remote
      attacker may be able to: trick users into downloading and executing
      arbitrary files, bypass intended access restrictions, spoof trusted
      content, spoof URLs, bypass the Same Origin Policy, obtain sensitive
      information, force subscriptions to arbitrary feeds, bypass the popup
      blocker, bypass CSS filtering, conduct cross-site scripting attacks, or
      have other unknown impact.
    A local attacker could perform symlink attacks to overwrite arbitrary
      files with the privileges of the user running the application or possibly
      obtain sensitive information.
    A physically proximate attacker may be able to access an email account.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/opera-12.00.1467'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 94, 264, 287, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 12.00.1467"), vulnerable:make_list("lt 12.00.1467"))) flag++;

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
