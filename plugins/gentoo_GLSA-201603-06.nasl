#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201603-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(89899);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/14 14:55:46 $");

  script_cve_id("CVE-2013-0860", "CVE-2013-0861", "CVE-2013-0862", "CVE-2013-0863", "CVE-2013-0864", "CVE-2013-0865", "CVE-2013-0866", "CVE-2013-0867", "CVE-2013-0868", "CVE-2013-0872", "CVE-2013-0873", "CVE-2013-0874", "CVE-2013-0875", "CVE-2013-0876", "CVE-2013-0877", "CVE-2013-0878", "CVE-2013-4263", "CVE-2013-4264", "CVE-2013-4265", "CVE-2013-7008", "CVE-2013-7009", "CVE-2013-7010", "CVE-2013-7011", "CVE-2013-7012", "CVE-2013-7013", "CVE-2013-7014", "CVE-2013-7015", "CVE-2013-7016", "CVE-2013-7017", "CVE-2013-7018", "CVE-2013-7019", "CVE-2013-7020", "CVE-2013-7021", "CVE-2013-7022", "CVE-2013-7023", "CVE-2013-7024", "CVE-2014-2097", "CVE-2014-2098", "CVE-2014-2263", "CVE-2014-5271", "CVE-2014-5272", "CVE-2014-7937", "CVE-2014-8541", "CVE-2014-8542", "CVE-2014-8543", "CVE-2014-8544", "CVE-2014-8545", "CVE-2014-8546", "CVE-2014-8547", "CVE-2014-8548", "CVE-2014-8549", "CVE-2014-9316", "CVE-2014-9317", "CVE-2014-9318", "CVE-2014-9319", "CVE-2014-9602", "CVE-2014-9603", "CVE-2014-9604", "CVE-2015-3395");
  script_xref(name:"GLSA", value:"201603-06");

  script_name(english:"GLSA-201603-06 : FFmpeg: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201603-06
(FFmpeg: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in FFmpeg.  Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code or cause a
      Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201603-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All FFmpeg users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-video/ffmpeg-2.6.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
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

if (qpkg_check(package:"media-video/ffmpeg", unaffected:make_list("ge 2.6.3"), vulnerable:make_list("lt 2.6.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "FFmpeg");
}
