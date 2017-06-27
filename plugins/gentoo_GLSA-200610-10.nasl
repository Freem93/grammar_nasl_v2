#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200610-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22913);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:52 $");

  script_cve_id("CVE-2006-4182");
  script_osvdb_id(29773, 29774);
  script_xref(name:"GLSA", value:"200610-10");

  script_name(english:"GLSA-200610-10 : ClamAV: Multiple Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200610-10
(ClamAV: Multiple Vulnerabilities)

    Damian Put and an anonymous researcher reported a potential heap-based
    buffer overflow vulnerability in rebuildpe.c responsible for the
    rebuilding of an unpacked PE file, and a possible crash in chmunpack.c
    in the CHM unpacker.
  
Impact :

    By sending a malicious attachment to a mail server running ClamAV, or
    providing a malicious file to ClamAV through any other method, a remote
    attacker could cause a Denial of Service and potentially the execution
    of arbitrary code with the permissions of the user running ClamAV.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/project/shownotes.php?release_id=455799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200610-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-antivirus/clamav-0.88.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/15");
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

if (qpkg_check(package:"app-antivirus/clamav", unaffected:make_list("ge 0.88.5"), vulnerable:make_list("lt 0.88.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ClamAV");
}
