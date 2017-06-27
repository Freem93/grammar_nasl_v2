#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201603-14.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(89907);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/20 14:41:41 $");

  script_cve_id("CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0400", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0412", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4734", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4871", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_xref(name:"GLSA", value:"201603-14");

  script_name(english:"GLSA-201603-14 : IcedTea: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201603-14
(IcedTea: Multiple vulnerabilities)

    Various OpenJDK attack vectors in IcedTea, such as 2D, Corba, Hotspot,
      Libraries, and JAXP, exist which allows remote attackers to affect the
      confidentiality, integrity, and availability of vulnerable systems.  This
      includes the possibility of remote execution of arbitrary code,
      information disclosure, or Denial of Service.  Many of the
      vulnerabilities can only be exploited through sandboxed Java Web Start
      applications and java applets.  Please reference the CVEs listed for
      specific details.
  
Impact :

    Remote attackers may remotely execute arbitrary code, compromise
      information, or cause Denial of Service.
  
Workaround :

    There is no known work around at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201603-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"IcedTea 7.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-7.2.6.4'
    IcedTea bin 7.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-bin-7.2.6.4'
    IcedTea 6.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-6.1.13.9'
    IcedTea bin 6.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-bin-6.1.13.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:icedtea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:icedtea-bin");
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

if (qpkg_check(package:"dev-java/icedtea", unaffected:make_list("ge 7.2.6.4", "rge 6.1.13.9", "lt 6"), vulnerable:make_list("lt 7.2.6.4"))) flag++;
if (qpkg_check(package:"dev-java/icedtea-bin", unaffected:make_list("ge 7.2.6.4", "rge 6.1.13.9", "lt 6"), vulnerable:make_list("lt 7.2.6.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IcedTea");
}
