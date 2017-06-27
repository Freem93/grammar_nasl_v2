#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200805-19.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32417);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-0314", "CVE-2008-1100", "CVE-2008-1387", "CVE-2008-1833", "CVE-2008-1835", "CVE-2008-1836", "CVE-2008-1837");
  script_osvdb_id(44370, 44519, 44520, 44521, 44522, 44523, 44524);
  script_xref(name:"GLSA", value:"200805-19");

  script_name(english:"GLSA-200805-19 : ClamAV: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200805-19
(ClamAV: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported:
    Damian Put reported a heap-based buffer overflow when processing PeSpin
    packed PE binaries (CVE-2008-0314).
    Alin Rad Pop of Secunia Research reported a buffer overflow in the
    cli_scanpe() function when processing Upack PE binaries
    (CVE-2008-1100).
    Hanno Boeck reported an infinite loop when processing ARJ archives
    (CVE-2008-1387).
    Damian Put and Thomas Pollet reported a heap-based buffer overflow when
    processing WWPack compressed PE binaries (CVE-2008-1833).
    A buffer over-read was discovered in the rfc2231() function when
    producing a string that is not NULL terminated (CVE-2008-1836).
    An unspecified vulnerability leading to 'memory problems' when scanning
    RAR files was reported (CVE-2008-1837).
    Thierry Zoller reported that scanning of RAR files could be
    circumvented (CVE-2008-1835).
  
Impact :

    A remote attacker could entice a user or automated system to scan a
    specially crafted file, possibly leading to the execution of arbitrary
    code with the privileges of the user running ClamAV (either a system
    user or the 'clamav' user if clamd is compromised), or a Denial of
    Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200805-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-antivirus/clamav-0.93'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-antivirus/clamav", unaffected:make_list("ge 0.93"), vulnerable:make_list("lt 0.93"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ClamAV");
}
