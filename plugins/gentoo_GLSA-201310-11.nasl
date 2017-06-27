#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201310-11.
#
# The advisory text is Copyright (C) 2001-2014 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/2.5/
#

include("compat.inc");

if (description)
{
  script_id(70487);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/07 21:49:47 $");

  script_cve_id("CVE-2011-4115");
  script_bugtraq_id(50537);
  script_osvdb_id(76908);
  script_xref(name:"GLSA", value:"201310-11");

  script_name(english:"GLSA-201310-11 : Perl Parallel-ForkManager Module: Insecure temporary file usage");
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
"The remote host is affected by the vulnerability described in GLSA-201310-11
(Perl Parallel-ForkManager Module: Insecure temporary file usage)

    The Perl Parallel-ForkManager module does not handle temporary files
      securely.
  
Impact :

    A local attacker could perform symlink attacks to overwrite arbitrary
      files with the privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-201310-11.xml"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Parallel-ForkManager users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-perl/Parallel-ForkManager-1.20.0'"
  );

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:Parallel-ForkManager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-perl/Parallel-ForkManager", unaffected:make_list("ge 1.20.0"), vulnerable:make_list("lt 1.20.0"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Perl Parallel-ForkManager Module");
}
