#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200410-31.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15587);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-1096");
  script_osvdb_id(10963);
  script_xref(name:"GLSA", value:"200410-31");

  script_name(english:"GLSA-200410-31 : Archive::Zip: Virus detection evasion");
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
"The remote host is affected by the vulnerability described in GLSA-200410-31
(Archive::Zip: Virus detection evasion)

    Archive::Zip can be used by email scanning software (like amavisd-new)
    to uncompress attachments before virus scanning. By modifying the
    uncompressed size of archived files in the global header of the ZIP
    file, it is possible to fool Archive::Zip into thinking some files
    inside the archive have zero length.
  
Impact :

    An attacker could send a carefully crafted ZIP archive containing a
    virus file and evade detection on some email virus-scanning software
    relying on Archive::Zip for decompression.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.idefense.com/application/poi/display?id=153
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b74b0112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rt.cpan.org/NoAuth/Bug.html?id=8077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200410-31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Archive::Zip users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-perl/Archive-Zip-1.14'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:Archive-Zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-perl/Archive-Zip", unaffected:make_list("ge 1.14"), vulnerable:make_list("lt 1.14"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Archive::Zip");
}
