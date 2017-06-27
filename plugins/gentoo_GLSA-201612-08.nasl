#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201612-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(95523);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id("CVE-2014-2830");
  script_xref(name:"GLSA", value:"201612-08");

  script_name(english:"GLSA-201612-08 : LinuxCIFS utils: Buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-201612-08
(LinuxCIFS utils: Buffer overflow)

    A stack-based buffer overflow was discovered in cifskey.c or cifscreds.c
      in LinuxCIFS, as used in &ldquo;pam_cifscreds.&rdquo;
  
Impact :

    A remote attacker could exploit this vulnerability to cause an
      unspecified impact.
  
Workaround :

    Don&rsquo;t use LinuxCIFS utils&rsquo; &ldquo;cifscreds&rdquo; PAM module. In Gentoo,
      LinuxCIFS utils&rsquo; PAM support is disabled by default unless the
      &ldquo;pam&rdquo; USE flag is enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201612-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All LinuxCIFS utils users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-fs/cifs-utils-6.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cifs-utils");
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

if (qpkg_check(package:"net-fs/cifs-utils", unaffected:make_list("ge 6.4"), vulnerable:make_list("lt 6.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LinuxCIFS utils");
}
