#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200612-15.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(23867);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:52 $");

  script_cve_id("CVE-2006-6474");
  script_osvdb_id(31295);
  script_xref(name:"GLSA", value:"200612-15");

  script_name(english:"GLSA-200612-15 : McAfee VirusScan: Insecure DT_RPATH");
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
"The remote host is affected by the vulnerability described in GLSA-200612-15
(McAfee VirusScan: Insecure DT_RPATH)

    Jakub Moc of Gentoo Linux discovered that McAfee VirusScan was
    distributed with an insecure DT_RPATH which included the current
    working directory, rather than $ORIGIN which was probably intended.
  
Impact :

    An attacker could entice a VirusScan user to scan an arbitrary file and
    execute arbitrary code with the privileges of the VirusScan user by
    tricking the dynamic loader into loading an untrusted ELF DSO. An
    automated system, such as a mail scanner, may be subverted to execute
    arbitrary code with the privileges of the process invoking VirusScan.
  
Workaround :

    Do not scan files or execute VirusScan from an untrusted working
    directory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200612-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"As VirusScan verifies that it has not been modified before executing,
    it is not possible to correct the DT_RPATH. Furthermore, this would
    violate the license that VirusScan is distributed under. For this
    reason, the package has been masked in Portage pending the resolution
    of this issue.
    # emerge --ask --verbose --unmerge 'app-antivirus/vlnx'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vlnx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-antivirus/vlnx", unaffected:make_list(), vulnerable:make_list("le 4510e"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "McAfee VirusScan");
}
