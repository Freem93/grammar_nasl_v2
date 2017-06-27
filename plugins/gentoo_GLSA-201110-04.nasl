#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56446);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-3235", "CVE-2009-3897", "CVE-2010-0745", "CVE-2010-3304", "CVE-2010-3706", "CVE-2010-3707", "CVE-2010-3779", "CVE-2010-3780", "CVE-2011-1929", "CVE-2011-2166", "CVE-2011-2167");
  script_bugtraq_id(36377, 37084, 41964, 43690, 47930, 48003);
  script_osvdb_id(58103, 60316, 64783, 66625, 68512, 68513, 68515, 68516, 72495, 74514, 74515);
  script_xref(name:"GLSA", value:"201110-04");

  script_name(english:"GLSA-201110-04 : Dovecot: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-04
(Dovecot: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Dovecot. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could exploit these vulnerabilities to cause the
      remote execution of arbitrary code, or a Denial of Service condition, to
      conduct directory traversal attacks, corrupt data, or disclose
      information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Dovecot 1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-mail/dovecot-1.2.17'
    All Dovecot 2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-mail/dovecot-2.0.13'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since May 28, 2011. It is likely that your system is already no
      longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-mail/dovecot", unaffected:make_list("rge 1.2.17", "ge 2.0.13"), vulnerable:make_list("lt 2.0.13"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Dovecot");
}
