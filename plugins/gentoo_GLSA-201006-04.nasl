#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201006-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(46771);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5235", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5238", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5242", "CVE-2008-5243", "CVE-2008-5244", "CVE-2008-5245", "CVE-2008-5246", "CVE-2008-5247", "CVE-2008-5248", "CVE-2009-0698", "CVE-2009-1274");
  script_bugtraq_id(30698, 30699, 30797, 33502, 34384);
  script_osvdb_id(47158, 47678, 47679, 47741, 47743, 47745, 47746, 47748, 47749, 47750, 47751, 50528, 50529, 50909, 50910, 52498, 52938, 52939, 52940, 52941, 52942, 52943, 53288);
  script_xref(name:"GLSA", value:"201006-04");

  script_name(english:"GLSA-201006-04 : xine-lib: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-201006-04
(xine-lib: User-assisted execution of arbitrary code)

    Multiple vulnerabilities have been reported in xine-lib. Please review
    the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to play a specially crafted video
    file or stream with a player using xine-lib, potentially resulting in
    the execution of arbitrary code with the privileges of the user running
    the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201006-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All xine-lib users should upgrade to an unaffected version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/xine-lib-1.1.16.3'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
    available since April 10, 2009. It is likely that your system is
    already no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/02");
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

if (qpkg_check(package:"media-libs/xine-lib", unaffected:make_list("ge 1.1.16.3"), vulnerable:make_list("lt 1.1.16.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xine-lib");
}
