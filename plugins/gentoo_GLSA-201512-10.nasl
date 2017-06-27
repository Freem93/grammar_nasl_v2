#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201512-10.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(87710);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2015-0798", "CVE-2015-0799", "CVE-2015-0801", "CVE-2015-0802", "CVE-2015-0803", "CVE-2015-0804", "CVE-2015-0805", "CVE-2015-0806", "CVE-2015-0807", "CVE-2015-0808", "CVE-2015-0810", "CVE-2015-0811", "CVE-2015-0812", "CVE-2015-0813", "CVE-2015-0814", "CVE-2015-0815", "CVE-2015-0816", "CVE-2015-2706", "CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2727", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730", "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2742", "CVE-2015-2743", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4153", "CVE-2015-4495", "CVE-2015-4513", "CVE-2015-4514", "CVE-2015-4515", "CVE-2015-4518", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7187", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7191", "CVE-2015-7192", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7195", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200", "CVE-2015-7201", "CVE-2015-7202", "CVE-2015-7203", "CVE-2015-7204", "CVE-2015-7205", "CVE-2015-7207", "CVE-2015-7208", "CVE-2015-7210", "CVE-2015-7211", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7215", "CVE-2015-7216", "CVE-2015-7217", "CVE-2015-7218", "CVE-2015-7219", "CVE-2015-7220", "CVE-2015-7221", "CVE-2015-7222", "CVE-2015-7223");
  script_xref(name:"GLSA", value:"201512-10");

  script_name(english:"GLSA-201512-10 : Mozilla Products: Multiple vulnerabilities (Bar Mitzvah) (Logjam)");
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
"The remote host is affected by the vulnerability described in GLSA-201512-10
(Mozilla Products: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Firefox and
      Mozilla Thunderbird. Please review the CVE identifiers referenced below
      for details.
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
      page or email, possibly resulting in execution of arbitrary code or a
      Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201512-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All  Firefox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-38.5.0'
    All  Firefox-bin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-38.5.0'
    All  Thunderbird users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-38.5.0'
    All  Thunderbird-bin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-38.5.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox PDF.js Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-client/thunderbird-bin", unaffected:make_list("ge 38.5.0"), vulnerable:make_list("lt 38.5.0"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird", unaffected:make_list("ge 38.5.0"), vulnerable:make_list("lt 38.5.0"))) flag++;
if (qpkg_check(package:"www-client/firefox-bin", unaffected:make_list("ge 38.5.0"), vulnerable:make_list("lt 38.5.0"))) flag++;
if (qpkg_check(package:"www-client/firefox", unaffected:make_list("ge 38.5.0"), vulnerable:make_list("lt 38.5.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Products");
}
