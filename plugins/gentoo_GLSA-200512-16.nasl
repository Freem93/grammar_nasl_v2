#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200512-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20357);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3964");
  script_xref(name:"GLSA", value:"200512-16");

  script_name(english:"GLSA-200512-16 : OpenMotif, AMD64 x86 emulation X libraries: Buffer overflows in libUil library");
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
"The remote host is affected by the vulnerability described in GLSA-200512-16
(OpenMotif, AMD64 x86 emulation X libraries: Buffer overflows in libUil library)

    xfocus discovered two potential buffer overflows in the libUil library,
    in the diag_issue_diagnostic and open_source_file functions.
  
Impact :

    Remotely-accessible or SUID applications making use of the affected
    functions might be exploited to execute arbitrary code with the
    privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7409d64c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200512-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenMotif users should upgrade to an unaffected version:
    # emerge --sync
    # emerge --ask --oneshot --unmerge --verbose x11-libs/openmotif
    # emerge --ask --oneshot --verbose x11-libs/openmotif
    All AMD64 x86 emulation X libraries users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-emulation/emul-linux-x86-xlibs"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-xlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openmotif");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);


flag = 0;

if (qpkg_check(package:"x11-libs/openmotif", unaffected:make_list("ge 2.2.3-r8", "rge 2.1.30-r13"), vulnerable:make_list("lt 2.2.3-r8"))) flag++;
if (qpkg_check(package:"app-emulation/emul-linux-x86-xlibs", arch:"amd64", unaffected:make_list("ge 2.2.1"), vulnerable:make_list("lt 2.2.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenMotif / AMD64 x86 emulation X libraries");
}
