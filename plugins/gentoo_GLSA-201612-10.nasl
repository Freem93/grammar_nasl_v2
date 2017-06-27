#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201612-10.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(95525);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id("CVE-2015-5313");
  script_xref(name:"GLSA", value:"201612-10");

  script_name(english:"GLSA-201612-10 : libvirt: Directory traversal");
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
"The remote host is affected by the vulnerability described in GLSA-201612-10
(libvirt: Directory traversal)

    Normally, only privileged users can coerce libvirt into creating or
      opening existing files using the virStorageVol APIs; and such users
      already have full privilege to create any domain XML.
    But in the case of fine-grained ACLs, it is feasible that a user can be
      granted storage_vol:create but not domain:write, and it violates
      assumptions if such a user can abuse libvirt to access files outside of
      the storage pool.
  
Impact :

    When fine-grained Access Control Lists (ACL) are in effect, an
      authenticated local user with storage_vol:create permission but without
      domain:write permission maybe able to create or access arbitrary files
      outside of the storage pool.
  
Workaround :

    Don&rsquo;t make use of fine-grained Access Control Lists (ACL) in libvirt;
      In Gentoo, libvirt&rsquo;s ACL support is disable by default unless you
      enable the &ldquo;policykit&rdquo; USE flag."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201612-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libvirt users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/libvirt-1.2.21-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/04");
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

if (qpkg_check(package:"app-emulation/libvirt", unaffected:make_list("ge 1.2.21-r1"), vulnerable:make_list("lt 1.2.21-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
