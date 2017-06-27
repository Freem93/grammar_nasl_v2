#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200702-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24722);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:56:53 $");

  script_cve_id("CVE-2006-3788", "CVE-2006-3789", "CVE-2006-3790", "CVE-2006-3791", "CVE-2006-3792");
  script_xref(name:"GLSA", value:"200702-10");

  script_name(english:"GLSA-200702-10 : UFO2000: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200702-10
(UFO2000: Multiple vulnerabilities)

    Five vulnerabilities were found: a buffer overflow in recv_add_unit();
    a problem with improperly trusting user-supplied string information in
    decode_stringmap(); several issues with array manipulation via various
    commands during play; a SQL injection in server_protocol.cpp; and
    finally, a second buffer overflow in recv_map_data().
  
Impact :

    An attacker could send crafted network traffic as part of a
    multi-player game that could result in remote code execution on the
    remote opponent or the server. A remote attacker could also run
    arbitrary SQL queries against the server account database, and perform
    a Denial of Service on a remote opponent by causing the game to crash.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200608-14.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200702-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"UFO2000 currently depends on the dumb-0.9.2 library, which has been
    removed from portage due to security problems (GLSA 200608-14) .
    Because of this, UFO2000 has been masked, and we recommend unmerging
    the package until the next beta release can remove the dependency on
    dumb.
    # emerge --ask --verbose --unmerge ufo2000"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ufo2000");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"games-strategy/ufo2000", unaffected:make_list("ge 0.7.1062"), vulnerable:make_list("lt 0.7.1062"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "UFO2000");
}
