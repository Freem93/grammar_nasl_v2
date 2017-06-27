#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201512-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(87516);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/21 14:44:24 $");

  script_cve_id("CVE-2015-8370");
  script_xref(name:"GLSA", value:"201512-03");

  script_name(english:"GLSA-201512-03 : GRUB: Authentication bypass");
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
"The remote host is affected by the vulnerability described in GLSA-201512-03
(GRUB: Authentication bypass)

    An integer underflow in GRUB&rsquo;s username/password authentication code
      has been discovered.
  
Impact :

    An attacker with access to the system console may bypass the username
      prompt by entering a sequence of backspace characters, allowing them e.g.
      to get full access to GRUB&rsquo;s console or to load a customized kernel.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.gentoo.org/wiki/GRUB2_Quick_Start"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201512-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GRUB 2.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-boot/grub-2.02_beta2-r8'
    After upgrading, make sure to run the grub2-install command with options
      appropriate for your system. See the GRUB2 Quick Start guide in the
      references below for examples. Your system will be vulnerable until this
      action is performed."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:grub");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"sys-boot/grub", unaffected:make_list("ge 2.02_beta2-r8", "rge 0.97"), vulnerable:make_list("lt 2.02_beta2-r8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GRUB");
}
