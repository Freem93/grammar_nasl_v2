#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200502-18.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16459);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0444");
  script_osvdb_id(13823);
  script_xref(name:"GLSA", value:"200502-18");

  script_name(english:"GLSA-200502-18 : VMware Workstation: Untrusted library search path");
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
"The remote host is affected by the vulnerability described in GLSA-200502-18
(VMware Workstation: Untrusted library search path)

    Tavis Ormandy of the Gentoo Linux Security Audit Team has discovered
    that VMware Workstation searches for gdk-pixbuf loadable modules in an
    untrusted, world-writable directory.
  
Impact :

    A local attacker could create a malicious shared object that would be
    loaded by VMware, resulting in the execution of arbitrary code with the
    privileges of the user running VMware.
  
Workaround :

    The system administrator may create the file /tmp/rrdharan to prevent
    malicious users from creating a directory at that location:
    # touch /tmp/rrdharan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200502-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VMware Workstation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/vmware-workstation-3.2.1.2242-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vmware-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/14");
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

if (qpkg_check(package:"app-emulation/vmware-workstation", unaffected:make_list("ge 4.5.2.8848-r5", "rge 3.2.1.2242-r4"), vulnerable:make_list("lt 4.5.2.8848-r5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VMware Workstation");
}
