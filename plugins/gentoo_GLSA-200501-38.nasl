#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-38.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16429);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2004-0452", "CVE-2005-0077", "CVE-2005-0448");
  script_osvdb_id(12588, 13186);
  script_xref(name:"GLSA", value:"200501-38");

  script_name(english:"GLSA-200501-38 : Perl: rmtree and DBI tmpfile vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200501-38
(Perl: rmtree and DBI tmpfile vulnerabilities)

    Javier Fernandez-Sanguino Pena discovered that the DBI library creates
    temporary files in an insecure, predictable way (CAN-2005-0077). Paul
    Szabo found out that 'File::Path::rmtree' is vulnerable to various race
    conditions (CAN-2004-0452, CAN-2005-0448).
  
Impact :

    A local attacker could create symbolic links in the temporary files
    directory that point to a valid file somewhere on the filesystem. When
    the DBI library or File::Path::rmtree is executed, this could be used
    to overwrite or remove files with the rights of the user calling these
    functions.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-38"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl
    All DBI library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-perl/DBI"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:DBI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-perl/DBI", unaffected:make_list("rge 1.37-r1", "ge 1.38-r1"), vulnerable:make_list("le 1.38"))) flag++;
if (qpkg_check(package:"dev-lang/perl", unaffected:make_list("ge 5.8.6-r4", "rge 5.8.5-r5", "rge 5.8.4-r4", "rge 5.8.2-r4"), vulnerable:make_list("le 5.8.6-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Perl");
}
