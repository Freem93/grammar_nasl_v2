#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201403-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(73127);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/13 14:27:08 $");

  script_cve_id("CVE-2012-0035", "CVE-2012-3479");
  script_bugtraq_id(51354, 54969);
  script_osvdb_id(78244, 84691);
  script_xref(name:"GLSA", value:"201403-05");

  script_name(english:"GLSA-201403-05 : GNU Emacs: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201403-05
(GNU Emacs: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in GNU Emacs:
      When &lsquo;global-ede-mode&rsquo; is enabled, EDE in Emacs automatically
        loads a Project.ede file from the project directory (CVE-2012-0035).
      When &lsquo;enable-local-variables&rsquo;&rsquo; is set to &lsquo;:safe&rsquo;, Emacs
        automatically processes eval forms (CVE-2012-3479).
  
Impact :

    A remote attacker could entice a user to open a specially crafted file,
      possibly resulting in execution of arbitrary code with the privileges of
      the process or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201403-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GNU Emacs 24.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-editors/emacs-24.1-r1'
    All GNU Emacs 23.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-editors/emacs-23.4-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emacs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-editors/emacs", unaffected:make_list("ge 24.1-r1", "rge 23.4-r4", "lt 23.2"), vulnerable:make_list("lt 24.1-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GNU Emacs");
}
