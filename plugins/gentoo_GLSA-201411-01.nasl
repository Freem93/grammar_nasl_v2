#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201411-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(78879);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2010-1441", "CVE-2010-1442", "CVE-2010-1443", "CVE-2010-1444", "CVE-2010-1445", "CVE-2010-2062", "CVE-2010-2937", "CVE-2010-3124", "CVE-2010-3275", "CVE-2010-3276", "CVE-2010-3907", "CVE-2011-0021", "CVE-2011-0522", "CVE-2011-0531", "CVE-2011-1087", "CVE-2011-1684", "CVE-2011-2194", "CVE-2011-2587", "CVE-2011-2588", "CVE-2011-3623", "CVE-2012-0023", "CVE-2012-1775", "CVE-2012-1776", "CVE-2012-2396", "CVE-2012-3377", "CVE-2012-5470", "CVE-2012-5855", "CVE-2013-1868", "CVE-2013-1954", "CVE-2013-3245", "CVE-2013-4388", "CVE-2013-6283", "CVE-2013-6934");
  script_bugtraq_id(42386, 45632, 45927, 46008, 46060, 47012, 47293, 48171, 48664, 51231, 52550, 53391, 53535, 54345, 55850, 57079, 57333, 61032, 61844, 62724, 65139);
  script_xref(name:"GLSA", value:"201411-01");

  script_name(english:"GLSA-201411-01 : VLC: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201411-01
(VLC: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in VLC. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted media
      file using VLC, possibly resulting in execution of arbitrary code with
      the privileges of the process or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201411-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VLC users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-video/vlc-2.1.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VLC MMS Stream Handling Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-video/vlc", unaffected:make_list("ge 2.1.2"), vulnerable:make_list("lt 2.1.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VLC");
}
