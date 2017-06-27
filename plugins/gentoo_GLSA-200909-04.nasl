#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200909-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(40912);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-6680", "CVE-2009-1270", "CVE-2009-1371", "CVE-2009-1372");
  script_osvdb_id(53461, 53598, 53602, 53603);
  script_xref(name:"GLSA", value:"200909-04");

  script_name(english:"GLSA-200909-04 : Clam AntiVirus: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200909-04
(Clam AntiVirus: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in ClamAV:
    The
    vendor reported a Divide-by-zero error in the PE ('Portable
    Executable'; Windows .exe) file handling of ClamAV
    (CVE-2008-6680).
    Jeffrey Thomas Peckham found a flaw in
    libclamav/untar.c, possibly resulting in an infinite loop when
    processing TAR archives in clamd and clamscan (CVE-2009-1270).
    Martin Olsen reported a vulnerability in the CLI_ISCONTAINED macro
    in libclamav/others.h, when processing UPack archives
    (CVE-2009-1371).
    Nigel disclosed a stack-based buffer overflow
    in the 'cli_url_canon()' function in libclamav/phishcheck.c when
    processing URLs (CVE-2009-1372).
  
Impact :

    A remote attacker could entice a user or automated system to process a
    specially crafted UPack archive or a file containing a specially
    crafted URL, possibly resulting in the remote execution of arbitrary
    code with the privileges of the user running the application, or a
    Denial of Service. Furthermore, a remote attacker could cause a Denial
    of Service by supplying a specially crafted TAR archive or PE
    executable to a Clam AntiVirus instance.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200909-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Clam AntiVirus users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-antivirus/clamav-0.95.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-antivirus/clamav", unaffected:make_list("ge 0.95.2"), vulnerable:make_list("lt 0.95.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Clam AntiVirus");
}
