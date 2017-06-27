#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32009);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_cve_id("CVE-2008-1720");
  script_osvdb_id(44368);
  script_xref(name:"GLSA", value:"200804-16");

  script_name(english:"GLSA-200804-16 : rsync: Execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200804-16
(rsync: Execution of arbitrary code)

    Sebastian Krahmer of SUSE reported an integer overflow in the
    expand_item_list() function in the file util.c which might lead to a
    heap-based buffer overflow when extended attribute (xattr) support is
    enabled.
  
Impact :

    A remote attacker could send a file containing specially crafted
    extended attributes to an rsync deamon, or entice a user to sync from
    an rsync server containing specially crafted files, possibly leading to
    the execution of arbitrary code.
    Please note that extended attributes are only enabled when USE='acl' is
    enabled, which is the default setting.
  
Workaround :

    Disable extended attributes in the rsync daemon by setting 'refuse
    options = xattrs' in the file '/etc/rsyncd.conf' (or append
    'xattrs' to an existing 'refuse' statement). When synchronizing to a
    server, do not provide the '-X' parameter to rsync. You can also
    disable the 'acl' USE flag for rsync and recompile the package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All rsync users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/rsync-2.6.9-r6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/rsync", unaffected:make_list("ge 2.6.9-r6"), vulnerable:make_list("lt 2.6.9-r6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsync");
}
