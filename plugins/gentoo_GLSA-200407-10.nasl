#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14543);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0426");
  script_osvdb_id(5731);
  script_xref(name:"GLSA", value:"200407-10");

  script_name(english:"GLSA-200407-10 : rsync: Directory traversal in rsync daemon");
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
"The remote host is affected by the vulnerability described in GLSA-200407-10
(rsync: Directory traversal in rsync daemon)

    When rsyncd is used without chroot ('use chroot = false' in the rsyncd.conf
    file), the paths sent by the client are not checked thoroughly enough. If
    rsyncd is used with read-write permissions ('read only = false'), this
    vulnerability can be used to write files anywhere with the rights of the
    rsyncd daemon. With default Gentoo installations, rsyncd runs in a chroot,
    without write permissions and with the rights of the 'nobody' user.
  
Impact :

    On affected configurations and if the rsync daemon runs under a privileged
    user, a remote client can exploit this vulnerability to completely
    compromise the host.
  
Workaround :

    You should never set the rsync daemon to run with 'use chroot = false'. If
    for some reason you have to run rsyncd without a chroot, then you should
    not set 'read only = false'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should update to the latest version of the rsync package.
    # emerge sync
    # emerge -pv '>=net-misc/rsync-2.6.0-r2'
    # emerge '>=net-misc/rsync-2.6.0-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/29");
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

if (qpkg_check(package:"net-misc/rsync", unaffected:make_list("ge 2.6.0-r2"), vulnerable:make_list("le 2.6.0-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsync");
}
