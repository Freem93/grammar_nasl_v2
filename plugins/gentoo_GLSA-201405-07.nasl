#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201405-07.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(74028);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2013-1056", "CVE-2013-1940", "CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1993", "CVE-2013-1994", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063", "CVE-2013-2064", "CVE-2013-2066", "CVE-2013-4396");
  script_bugtraq_id(59282, 60120, 60121, 60122, 60123, 60124, 60125, 60126, 60127, 60128, 60129, 60130, 60131, 60132, 60133, 60134, 60135, 60136, 60137, 60138, 60139, 60141, 60142, 60143, 60144, 60145, 60146, 60148, 60149, 60151, 62892, 63203);
  script_osvdb_id(93647, 93648, 93652, 93653, 93655, 93661, 93664, 93669, 93673, 93690, 98314);
  script_xref(name:"GLSA", value:"201405-07");

  script_name(english:"GLSA-201405-07 : X.Org X Server: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201405-07
(X.Org X Server: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in X.Org X Server. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A context-dependent attacker could execute arbitrary code with the
      privileges of the process, cause a Denial of Service condition, or obtain
      sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201405-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All X.Org X Server users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.14.3-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-base/xorg-server", unaffected:make_list("ge 1.14.3-r2"), vulnerable:make_list("lt 1.14.3-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X.Org X Server");
}
