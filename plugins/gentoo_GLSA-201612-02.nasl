#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201612-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(95517);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id("CVE-2013-4362");
  script_xref(name:"GLSA", value:"201612-02");

  script_name(english:"GLSA-201612-02 : DavFS2: Local privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-201612-02
(DavFS2: Local privilege escalation)

    DavFS2 installs &ldquo;/usr/sbin/mount.davfs&rdquo; as setuid root. This utility
      uses &ldquo;system()&rdquo; to call &ldquo;/sbin/modprobe&rdquo;.
    While the call to &ldquo;modprobe&rdquo; itself cannot be manipulated, a local
      authenticated user can set the &ldquo;MODPROBE_OPTIONS&rdquo; environment
      variable to pass a user controlled path, allowing the loading of an
      arbitrary kernel module.
  
Impact :

    A local user could gain root privileges.
  
Workaround :

    The system administrator should ensure that all modules the
      &ldquo;mount.davfs&rdquo; utility tries to load are loaded upon system boot
      before any local user can call the utility.
    An additional defense measure can be implemented by enabling the Linux
      kernel module signing feature. This assists in the prevention of
      arbitrary modules being loaded."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201612-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All DavFS2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-fs/davfs2-1.5.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:davfs2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-fs/davfs2", unaffected:make_list("ge 1.5.2"), vulnerable:make_list("lt 1.5.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "DavFS2");
}
