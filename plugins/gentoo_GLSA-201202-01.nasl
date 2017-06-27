#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201202-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(58025);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2011-3016", "CVE-2011-3017", "CVE-2011-3018", "CVE-2011-3019", "CVE-2011-3020", "CVE-2011-3021", "CVE-2011-3022", "CVE-2011-3023", "CVE-2011-3024", "CVE-2011-3025", "CVE-2011-3027", "CVE-2011-3953", "CVE-2011-3954", "CVE-2011-3955", "CVE-2011-3956", "CVE-2011-3957", "CVE-2011-3958", "CVE-2011-3959", "CVE-2011-3960", "CVE-2011-3961", "CVE-2011-3962", "CVE-2011-3963", "CVE-2011-3964", "CVE-2011-3965", "CVE-2011-3966", "CVE-2011-3967", "CVE-2011-3968", "CVE-2011-3969", "CVE-2011-3970", "CVE-2011-3971", "CVE-2011-3972");
  script_bugtraq_id(51911, 52031);
  script_osvdb_id(78933, 78934, 78935, 78936, 78937, 78938, 78940, 78941, 78942, 78943, 78944, 78945, 78946, 78947, 78948, 78949, 78950, 78951, 78952, 79284, 79285, 79286, 79287, 79288, 79289, 79290, 79291, 79292, 79293, 79295);
  script_xref(name:"GLSA", value:"201202-01");

  script_name(english:"GLSA-201202-01 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201202-01
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium. Please review
      the CVE identifiers and release notes referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted web
      site using Chromium, possibly resulting in the execution of arbitrary
      code with the privileges of the process, a Denial of Service condition,
      information leak (clipboard contents), bypass of the Same Origin Policy,
      or escape from NativeClient's sandbox.
    A remote attacker could also entice the user to perform a set of UI
      actions (drag and drop) to trigger an URL bar spoofing vulnerability.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://googlechromereleases.blogspot.com/2012/02/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?301ce561"
  );
  # http://googlechromereleases.blogspot.com/2012/02/chrome-stable-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f5d2c3f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201202-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-17.0.963.56'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 17.0.963.56"), vulnerable:make_list("lt 17.0.963.56"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
