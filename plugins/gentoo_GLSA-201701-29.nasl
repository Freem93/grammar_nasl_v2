#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201701-29.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(96423);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/12 14:54:53 $");

  script_cve_id("CVE-2016-1248");
  script_xref(name:"GLSA", value:"201701-29");

  script_name(english:"GLSA-201701-29 : Vim, gVim: Remote execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-201701-29
(Vim, gVim: Remote execution of arbitrary code)

    Vim and gVim do not properly validate values for the &lsquo;filetype&rsquo;,
      &lsquo;syntax&rsquo;, and &lsquo;keymap&rsquo; options.
  
Impact :

    A remote attacker could entice a user to open a specially crafted file
      using Vim/gVim with certain modeline options enabled possibly resulting
      in execution of arbitrary code with the privileges of the process.
  
Workaround :

    Disabling modeline support in .vimrc by adding &ldquo;set nomodeline&rdquo; will
      prevent exploitation of this flaw. By default, modeline is enabled for
      ordinary users but disabled for root."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201701-29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Vim users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-editors/vim-8.0.0106'
    All gVim users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-editors/gvim-8.0.0106'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-editors/vim", unaffected:make_list("ge 8.0.0106"), vulnerable:make_list("lt 8.0.0106"))) flag++;
if (qpkg_check(package:"app-editors/gvim", unaffected:make_list("ge 8.0.0106"), vulnerable:make_list("lt 8.0.0106"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Vim / gVim");
}
