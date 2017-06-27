#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-18.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14746);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0806");
  script_osvdb_id(9779);
  script_xref(name:"GLSA", value:"200409-18");

  script_name(english:"GLSA-200409-18 : cdrtools: Local root vulnerability in cdrecord if set SUID root");
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
"The remote host is affected by the vulnerability described in GLSA-200409-18
(cdrtools: Local root vulnerability in cdrecord if set SUID root)

    Max Vozeler discovered that the cdrecord utility, when set to SUID root,
    fails to drop root privileges before executing a user-supplied RSH program.
    By default, Gentoo does not ship the cdrecord utility as SUID root and
    therefore is not vulnerable. However, many users (and CD-burning
    front-ends) set this manually after installation.
  
Impact :

    A local attacker could specify a malicious program using the $RSH
    environment variable and have it executed by the SUID cdrecord, resulting
    in root privileges escalation.
  
Workaround :

    As a workaround, you could remove the SUID rights from your cdrecord
    utility :
    # chmod a-s /usr/bin/cdrecord"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All cdrtools users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=app-cdr/cdrtools-2.01_alpha37-r1'
    # emerge '>=app-cdr/cdrtools-2.01_alpha37-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cdrtools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/31");
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

if (qpkg_check(package:"app-cdr/cdrtools", unaffected:make_list("ge 2.01_alpha37-r1", "rge 2.01_alpha28-r2"), vulnerable:make_list("le 2.01_alpha37"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cdrtools");
}
