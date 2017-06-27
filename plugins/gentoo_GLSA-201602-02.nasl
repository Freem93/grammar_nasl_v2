#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201602-02.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(88822);
  script_version("$Revision: 2.15 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2013-7423", "CVE-2014-0475", "CVE-2014-5119", "CVE-2014-6040", "CVE-2014-7817", "CVE-2014-8121", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1781", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8778", "CVE-2015-8779");
  script_xref(name:"GLSA", value:"201602-02");
  script_xref(name:"IAVA", value:"2016-A-0053");
  script_xref(name:"TRA", value:"TRA-2017-08");

  script_name(english:"GLSA-201602-02 : GNU C Library: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201602-02
(GNU C Library: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in the GNU C Library:
      The Google Security Team and Red Hat discovered a stack-based buffer
        overflow in the send_dg() and send_vc() functions due to a buffer
        mismanagement when getaddrinfo() is called with AF_UNSPEC
        (CVE-2015-7547).
      The strftime() function access invalid memory when passed
        out-of-range data, resulting in a crash (CVE-2015-8776).
      An integer overflow was found in the __hcreate_r() function
        (CVE-2015-8778).
      Multiple unbounded stack allocations were found in the catopen()
        function (CVE-2015-8779).
    Please review the CVEs referenced below for additional vulnerabilities
      that had already been fixed in previous versions of sys-libs/glibc, for
      which we have not issued a GLSA before.
  
Impact :

    A remote attacker could exploit any application which performs host name
      resolution using getaddrinfo() in order to execute arbitrary code or
      crash the application. The other vulnerabilities can possibly be
      exploited to cause a Denial of Service or leak information.
  
Workaround :

    A number of mitigating factors for CVE-2015-7547 have been identified.
      Please review the upstream advisory and references below."
  );
  # https://googleonlinesecurity.blogspot.de/2016/02/cve-2015-7547-glibc-getaddrinfo-stack.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1358552a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201602-02"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU C Library users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-libs/glibc-2.21-r2'
    It is important to ensure that no running process uses the old glibc
      anymore. The easiest way to achieve that is by rebooting the machine
      after updating the sys-libs/glibc package.
    Note: Should you run into compilation failures while updating, please
      see bug 574948."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"sys-libs/glibc", unaffected:make_list("ge 2.21-r2"), vulnerable:make_list("lt 2.21-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU C Library");
}
