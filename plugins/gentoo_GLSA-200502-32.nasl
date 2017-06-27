#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200502-32.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17235);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0160", "CVE-2005-0161");
  script_osvdb_id(14058, 14059);
  script_xref(name:"GLSA", value:"200502-32");

  script_name(english:"GLSA-200502-32 : UnAce: Buffer overflow and directory traversal vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200502-32
(UnAce: Buffer overflow and directory traversal vulnerabilities)

    Ulf Harnhammar discovered that UnAce suffers from buffer overflows
    when testing, unpacking or listing specially crafted ACE archives
    (CAN-2005-0160). He also found out that UnAce is vulnerable to
    directory traversal attacks, if an archive contains './..' sequences or
    absolute filenames (CAN-2005-0161).
  
Impact :

    An attacker could exploit the buffer overflows to execute
    malicious code or the directory traversals to overwrite arbitrary
    files.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200502-32"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All UnAce users should upgrade to the latest available 1.2
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-arch/unace-1.2b-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:unace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/22");
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

if (qpkg_check(package:"app-arch/unace", unaffected:make_list("rge 1.2b-r1"), vulnerable:make_list("le 1.2b", "ge 2.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "UnAce");
}
