#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200909-14.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(40961);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-5917", "CVE-2009-0930", "CVE-2009-0931", "CVE-2009-0932", "CVE-2009-2360");
  script_bugtraq_id(33491, 33492);
  script_osvdb_id(51826, 51827, 51828, 51887, 51888, 53540, 55665);
  script_xref(name:"GLSA", value:"200909-14");

  script_name(english:"GLSA-200909-14 : Horde: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200909-14
(Horde: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Horde:
    Gunnar Wrobel reported an input sanitation and directory traversal
    flaw in framework/Image/Image.php, related to the 'Horde_Image driver
    name' (CVE-2009-0932).
    Gunnar Wrobel reported that data sent
    to horde/services/portal/cloud_search.php is not properly sanitized
    before used in the output (CVE-2009-0931).
    It was reported
    that data sent to framework/Text_Filter/Filter/xss.php is not properly
    sanitized before used in the output (CVE-2008-5917).
    Horde Passwd: David Wharton reported that data sent via the 'backend'
    parameter to passwd/main.php is not properly sanitized before used in
    the output (CVE-2009-2360).
    Horde IMP: Gunnar Wrobel reported that data sent to smime.php, pgp.php,
    and message.php is not properly sanitized before used in the output
    (CVE-2009-0930).
  
Impact :

    A remote authenticated attacker could exploit these vulnerabilities to
    execute arbitrary PHP files on the server, or disclose the content of
    arbitrary files, both only if the file is readable to the web server. A
    remote authenticated attacker could conduct Cross-Site Scripting
    attacks. NOTE: Some Cross-Site Scripting vectors are limited to the
    usage of Microsoft Internet Explorer.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200909-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Horde users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-3.3.4'
    All Horde IMP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-imp-4.3.4'
    All Horde Passwd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-passwd-3.1.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Horde < 3.3.2 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-imp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-passwd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/horde", unaffected:make_list("ge 3.3.4"), vulnerable:make_list("lt 3.3.4"))) flag++;
if (qpkg_check(package:"www-apps/horde-imp", unaffected:make_list("ge 4.3.4"), vulnerable:make_list("lt 4.3.4"))) flag++;
if (qpkg_check(package:"www-apps/horde-passwd", unaffected:make_list("ge 3.1.1"), vulnerable:make_list("lt 3.1.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Horde");
}
