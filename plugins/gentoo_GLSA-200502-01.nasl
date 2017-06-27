#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200502-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16438);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2005-0225");
  script_osvdb_id(13137);
  script_xref(name:"GLSA", value:"200502-01");

  script_name(english:"GLSA-200502-01 : FireHOL: Insecure temporary file creation");
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
"The remote host is affected by the vulnerability described in GLSA-200502-01
(FireHOL: Insecure temporary file creation)

    FireHOL insecurely creates temporary files with predictable names.
  
Impact :

    A local attacker could create malicious symbolic links to arbitrary
    system files. When FireHOL is executed, this could lead to these files
    being overwritten with the rights of the user launching FireHOL,
    usually the root user.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://cvs.sourceforge.net/viewcvs.py/firehol/firehol/firehol.sh
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.net-security.org/advisory.php?id=4420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200502-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All FireHOL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-firewall/firehol-1.224'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firehol");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/24");
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

if (qpkg_check(package:"net-firewall/firehol", unaffected:make_list("ge 1.224"), vulnerable:make_list("lt 1.224"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "FireHOL");
}
