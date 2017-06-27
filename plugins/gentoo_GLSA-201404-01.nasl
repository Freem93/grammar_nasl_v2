#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201404-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(73390);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/13 14:27:08 $");

  script_cve_id("CVE-2012-5519");
  script_bugtraq_id(56494);
  script_osvdb_id(87635);
  script_xref(name:"GLSA", value:"201404-01");

  script_name(english:"GLSA-201404-01 : CUPS: Arbitrary file read/write");
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
"The remote host is affected by the vulnerability described in GLSA-201404-01
(CUPS: Arbitrary file read/write)

    Members of the lpadmin group have admin access to the web interface,
      where they can
      edit the config file and set some &ldquo;dangerous&rdquo; directives (like the
      logfilenames), which enable them to read or write files as the user
      running
      the CUPS webserver.
  
Impact :

    A local attacker could possibly exploit this vulnerability to read or
      write files as the user running the CUPS webserver.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201404-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CUPS users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-print/cups-1.6.2-r5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-print/cups", unaffected:make_list("ge 1.6.2-r5"), vulnerable:make_list("lt 1.6.2-r5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CUPS");
}
