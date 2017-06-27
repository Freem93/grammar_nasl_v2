#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201001-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(44891);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-3794", "CVE-2009-3796", "CVE-2009-3797", "CVE-2009-3798", "CVE-2009-3799", "CVE-2009-3800");
  script_bugtraq_id(37266, 37267, 37269, 37270, 37273, 37275);
  script_osvdb_id(60885, 60886, 60887, 60888, 60889, 60890);
  script_xref(name:"GLSA", value:"201001-02");

  script_name(english:"GLSA-201001-02 : Adobe Flash Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201001-02
(Adobe Flash Player: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Flash Player:
    An anonymous researcher working with the Zero Day
    Initiative reported that Adobe Flash Player does not properly process
    JPEG files (CVE-2009-3794).
    Jim Cheng of EffectiveUI reported
    an unspecified data injection vulnerability (CVE-2009-3796).
    Bing Liu of Fortinet's FortiGuard Labs reported multiple
    unspecified memory corruption vulnerabilities (CVE-2009-3797,
    CVE-2009-3798).
    Damian Put reported an integer overflow in the
    Verifier::parseExceptionHandlers() function (CVE-2009-3799).
    Will Dormann of CERT reported multiple unspecified Denial of
    Service vulnerabilities (CVE-2009-3800).
  
Impact :

    A remote attacker could entice a user to open a specially crafted SWF
    file, possibly resulting in the remote execution of arbitrary code with
    the privileges of the user running the application, or a Denial of
    Service via unknown vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201001-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-10.0.42.34'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 10.0.42.34"), vulnerable:make_list("lt 10.0.42.34"))) flag++;

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
