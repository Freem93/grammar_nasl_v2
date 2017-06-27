#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200511-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20244);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3349", "CVE-2005-3355");
  script_osvdb_id(20939, 20940);
  script_xref(name:"GLSA", value:"200511-16");

  script_name(english:"GLSA-200511-16 : GNUMP3d: Directory traversal and insecure temporary file creation");
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
"The remote host is affected by the vulnerability described in GLSA-200511-16
(GNUMP3d: Directory traversal and insecure temporary file creation)

    Ludwig Nussel from SUSE Linux has identified two vulnerabilities in
    GNUMP3d. GNUMP3d fails to properly check for the existence of
    /tmp/index.lok before writing to the file, allowing for local
    unauthorized access to files owned by the user running GNUMP3d. GNUMP3d
    also fails to properly validate the 'theme' GET variable from CGI
    input, allowing for unauthorized file inclusion.
  
Impact :

    An attacker could overwrite files owned by the user running GNUMP3d by
    symlinking /tmp/index.lok to the file targeted for overwrite. An
    attacker could also include arbitrary files by traversing up the
    directory tree (at most two times, i.e. '../..') with the 'theme' GET
    variable.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gnu.org/software/gnump3d/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200511-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNUMP3d users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-sound/gnump3d-2.9_pre7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gnump3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/17");
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

if (qpkg_check(package:"media-sound/gnump3d", unaffected:make_list("ge 2.9_pre7"), vulnerable:make_list("lt 2.9_pre7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNUMP3d");
}
