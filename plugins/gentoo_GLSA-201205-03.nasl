#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201205-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59627);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/13 14:19:45 $");

  script_cve_id("CVE-2011-3083", "CVE-2011-3084", "CVE-2011-3085", "CVE-2011-3086", "CVE-2011-3087", "CVE-2011-3088", "CVE-2011-3089", "CVE-2011-3090", "CVE-2011-3091", "CVE-2011-3092", "CVE-2011-3093", "CVE-2011-3094", "CVE-2011-3095", "CVE-2011-3096", "CVE-2011-3100", "CVE-2011-3101");
  script_bugtraq_id(53540);
  script_osvdb_id(81945, 81946, 81947, 81948, 81949, 81950, 81951, 81952, 81953, 81954, 81955, 81956, 81957, 81958, 81962, 81963);
  script_xref(name:"GLSA", value:"201205-03");

  script_name(english:"GLSA-201205-03 : Chromium, V8: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201205-03
(Chromium, V8: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and V8. Please
      review the CVE identifiers and release notes referenced below for
      details.
  
Impact :

    A context-dependent attacker could entice a user to open a specially
      crafted website or JavaScript program using Chromium or V8, possibly
      resulting in the execution of arbitrary code with the privileges of the
      process, or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://googlechromereleases.blogspot.com/2012/05/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57869300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201205-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-19.0.1084.46'
    All V8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/v8-3.9.24.21'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 19.0.1084.46"), vulnerable:make_list("lt 19.0.1084.46"))) flag++;
if (qpkg_check(package:"dev-lang/v8", unaffected:make_list("ge 3.9.24.21"), vulnerable:make_list("lt 3.9.24.21"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / V8");
}
