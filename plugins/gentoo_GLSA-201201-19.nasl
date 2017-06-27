#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201201-19.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(57745);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2010-4091", "CVE-2011-0562", "CVE-2011-0563", "CVE-2011-0565", "CVE-2011-0566", "CVE-2011-0567", "CVE-2011-0570", "CVE-2011-0585", "CVE-2011-0586", "CVE-2011-0587", "CVE-2011-0588", "CVE-2011-0589", "CVE-2011-0590", "CVE-2011-0591", "CVE-2011-0592", "CVE-2011-0593", "CVE-2011-0594", "CVE-2011-0595", "CVE-2011-0596", "CVE-2011-0598", "CVE-2011-0599", "CVE-2011-0600", "CVE-2011-0602", "CVE-2011-0603", "CVE-2011-0604", "CVE-2011-0605", "CVE-2011-0606", "CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2137", "CVE-2011-2138", "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414", "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417", "CVE-2011-2424", "CVE-2011-2425", "CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434", "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438", "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442", "CVE-2011-2462", "CVE-2011-4369");
  script_bugtraq_id(44638, 46187, 46198, 46199, 46200, 46201, 46202, 46204, 46207, 46208, 46209, 46210, 46211, 46212, 46213, 46214, 46216, 46217, 46218, 46219, 46220, 46221, 46222, 46251, 46252, 46254, 46255, 49073, 49074, 49075, 49076, 49077, 49079, 49080, 49081, 49082, 49083, 49084, 49085, 49086, 49186, 49572, 49575, 49576, 49577, 49578, 49579, 49580, 49581, 49582, 49583, 49584, 49585, 50922, 51092);
  script_osvdb_id(69005, 71373, 71374, 71375, 71376, 71377, 71378, 71379, 71380, 71381, 71382, 71383, 71384, 71385, 71386, 71387, 71388, 71389, 71390, 71391, 71392, 71393, 71394, 71395, 71397, 71398, 71399, 72501, 74432, 74433, 74434, 74435, 74436, 74437, 74438, 74439, 74440, 74441, 74442, 74443, 74444, 75201, 75430, 75431, 75432, 75433, 75434, 75435, 75436, 75437, 75438, 75439, 75440, 75441, 77529, 78026, 97670, 97671, 97672);
  script_xref(name:"GLSA", value:"201201-19");

  script_name(english:"GLSA-201201-19 : Adobe Reader: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201201-19
(Adobe Reader: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Reader. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted PDF
      file using Adobe Reader, possibly resulting in the remote execution of
      arbitrary code, a Denial of Service, or other impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201201-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Reader users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-text/acroread-9.4.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Reader U3D Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");
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

if (qpkg_check(package:"app-text/acroread", unaffected:make_list("ge 9.4.7"), vulnerable:make_list("lt 9.4.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Reader");
}
