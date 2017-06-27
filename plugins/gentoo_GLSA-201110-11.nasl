#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56504);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560", "CVE-2011-0561", "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", "CVE-2011-0574", "CVE-2011-0575", "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0579", "CVE-2011-0589", "CVE-2011-0607", "CVE-2011-0608", "CVE-2011-0609", "CVE-2011-0611", "CVE-2011-0618", "CVE-2011-0619", "CVE-2011-0620", "CVE-2011-0621", "CVE-2011-0622", "CVE-2011-0623", "CVE-2011-0624", "CVE-2011-0625", "CVE-2011-0626", "CVE-2011-0627", "CVE-2011-0628", "CVE-2011-2107", "CVE-2011-2110", "CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2137", "CVE-2011-2138", "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414", "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417", "CVE-2011-2424", "CVE-2011-2425", "CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2428", "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444");
  script_bugtraq_id(46186, 46188, 46189, 46190, 46191, 46192, 46193, 46194, 46195, 46196, 46197, 46202, 46282, 46283, 46860, 47314, 47806, 47807, 47808, 47809, 47810, 47811, 47812, 47813, 47814, 47815, 47847, 47961, 48107, 48268, 49073, 49074, 49075, 49076, 49077, 49079, 49080, 49081, 49082, 49083, 49084, 49085, 49086, 49186, 49710, 49714, 49715, 49716, 49717, 49718);
  script_osvdb_id(70911, 70913, 70914, 70915, 70916, 70917, 70918, 70919, 70920, 70921, 70922, 70923, 70976, 71254, 71391, 71686, 72331, 72332, 72333, 72334, 72335, 72336, 72337, 72341, 72342, 72343, 72344, 72723, 73007, 73015, 73097, 74432, 74433, 74435, 74436, 74437, 74438, 74439, 74440, 74441, 74442, 74443, 74444, 75201, 75625, 75626, 75627, 75628, 75629, 75630);
  script_xref(name:"GLSA", value:"201110-11");

  script_name(english:"GLSA-201110-11 : Adobe Flash Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-11
(Adobe Flash Player: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Flash Player.
      Please review the CVE identifiers and Adobe Security Advisories and
      Bulletins referenced below for details.
  
Impact :

    By enticing a user to open a specially crafted SWF file a remote
      attacker could cause a Denial of Service or the execution of arbitrary
      code with the privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa11-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa11-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb11-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb11-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb11-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.adobe.com/support/security/bulletins/apsb11-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.adobe.com/support/security/bulletins/apsb11-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash Player users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-plugins/adobe-flash-10.3.183.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 10.3.183.10"), vulnerable:make_list("lt 10.3.183.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Flash Player");
}
