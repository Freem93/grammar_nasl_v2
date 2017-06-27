#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200801-07.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(30031);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-4324", "CVE-2007-4768", "CVE-2007-5275", "CVE-2007-6242", "CVE-2007-6243", "CVE-2007-6244", "CVE-2007-6245", "CVE-2007-6246");
  script_osvdb_id(40766, 41475, 41483, 41484, 41485, 41486, 41487, 41488, 41489, 51567);
  script_xref(name:"GLSA", value:"200801-07");

  script_name(english:"GLSA-200801-07 : Adobe Flash Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200801-07
(Adobe Flash Player: Multiple vulnerabilities)

    Flash contains a copy of PCRE which is vulnerable to a heap-based
    buffer overflow (GLSA 200711-30, CVE-2007-4768).
    Aaron Portnoy reported an unspecified vulnerability related to
    input validation (CVE-2007-6242).
    Jesse Michael and Thomas Biege reported that Flash does not
    correctly set memory permissions (CVE-2007-6246).
    Dan Boneh, Adam Barth, Andrew Bortz, Collin Jackson, and Weidong
    Shao reported that Flash does not pin DNS hostnames to a single IP
    addresses, allowing for DNS rebinding attacks (CVE-2007-5275).
    David Neu reported an error withing the implementation of the
    Socket and XMLSocket ActionScript 3 classes (CVE-2007-4324).
    Toshiharu Sugiyama reported that Flash does not sufficiently
    restrict the interpretation and usage of cross-domain policy files,
    allowing for easier cross-site scripting attacks (CVE-2007-6243).
    Rich Cannings reported a cross-site scripting vulnerability in the
    way the 'asfunction:' protocol was handled (CVE-2007-6244).
    Toshiharu Sugiyama discovered that Flash allows remote attackers to
    modify HTTP headers for client requests and conduct HTTP Request
    Splitting attacks (CVE-2007-6245).
  
Impact :

    A remote attacker could entice a user to open a specially crafted file
    (usually in a web browser), possibly leading to the execution of
    arbitrary code with the privileges of the user running the Adobe Flash
    Player. The attacker could also cause a user's machine to establish TCP
    sessions with arbitrary hosts, bypass the Security Sandbox Model,
    obtain sensitive information, port scan arbitrary hosts, or conduct
    cross-site-scripting attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200801-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-9.0.115.0'
    Please be advised that unaffected packages of the Adobe Flash Player
    have known problems when used from within the Konqueror and Opera
    browsers."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 9.0.115.0"), vulnerable:make_list("lt 9.0.115.0"))) flag++;

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
