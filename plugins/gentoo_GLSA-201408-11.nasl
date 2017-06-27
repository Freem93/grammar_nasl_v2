#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201408-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(77455);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/28 18:42:39 $");

  script_cve_id("CVE-2011-4718", "CVE-2013-1635", "CVE-2013-1643", "CVE-2013-1824", "CVE-2013-2110", "CVE-2013-3735", "CVE-2013-4113", "CVE-2013-4248", "CVE-2013-4635", "CVE-2013-4636", "CVE-2013-6420", "CVE-2013-6712", "CVE-2013-7226", "CVE-2013-7327", "CVE-2013-7345", "CVE-2014-0185", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943", "CVE-2014-2270", "CVE-2014-2497", "CVE-2014-3597", "CVE-2014-3981", "CVE-2014-4049", "CVE-2014-4670", "CVE-2014-5120");
  script_bugtraq_id(58224, 58766, 60411, 60728, 60731, 61128, 61776, 61929, 62373, 64018, 64225, 65533, 65596, 65668, 66002, 66233, 66406, 67118, 67759, 67765, 67837, 68007, 68513, 69322, 69375);
  script_osvdb_id(93968, 94063, 95152, 100440, 100979, 104208, 104502, 107559, 107560, 107725, 107994, 108947, 110250, 110251);
  script_xref(name:"GLSA", value:"201408-11");

  script_name(english:"GLSA-201408-11 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201408-11
(PHP: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PHP. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A context-dependent attacker can cause arbitrary code execution, create
      a Denial of Service condition, read or write arbitrary files, impersonate
      other servers, hijack a web session, or have other unspecified impact.
      Additionally, a local attacker could gain escalated privileges.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201408-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP 5.5 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.5.16'
    All PHP 5.4 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.4.32'
    All PHP 5.3 users should upgrade to the latest version. This release
      marks the end of life of the PHP 5.3 series. Future releases of this
      series are not planned. All PHP 5.3 users are encouraged to upgrade to
      the current stable version of PHP 5.5 or previous stable version of PHP
      5.4, which are supported till at least 2016 and 2015 respectively.
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.3.29'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/30");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.5.16", "rge 5.4.32", "rge 5.3.29", "rge 5.4.34", "rge 5.4.35", "rge 5.4.36", "rge 5.4.37", "rge 5.4.38", "rge 5.4.39", "rge 5.4.40", "rge 5.4.41", "rge 5.4.42", "rge 5.4.43", "rge 5.4.44", "rge 5.4.45", "rge 5.4.46"), vulnerable:make_list("lt 5.5.16"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
