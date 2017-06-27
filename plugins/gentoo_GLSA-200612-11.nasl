#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200612-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(23863);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_bugtraq_id(20246, 20247, 20248, 20249);
  script_osvdb_id(29260, 29261, 29262, 29263);
  script_xref(name:"GLSA", value:"200612-11");

  script_name(english:"GLSA-200612-11 : AMD64 x86 emulation base libraries: OpenSSL multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200612-11
(AMD64 x86 emulation base libraries: OpenSSL multiple vulnerabilities)

    Tavis Ormandy and Will Drewry, both of the Google Security Team,
    discovered that the SSL_get_shared_ciphers() function contains a buffer
    overflow vulnerability, and that the SSLv2 client code contains a flaw
    leading to a crash. Additionally, Dr. Stephen N. Henson found that the
    ASN.1 handler contains two Denial of Service vulnerabilities: while
    parsing an invalid ASN.1 structure and while handling certain types of
    public key.
  
Impact :

    An attacker could trigger the buffer overflow by sending a malicious
    suite of ciphers to an application using the vulnerable function, and
    thus execute arbitrary code with the rights of the user running the
    application. An attacker could also consume CPU and/or memory by
    exploiting the Denial of Service vulnerabilities. Finally, a malicious
    server could crash a SSLv2 client through the SSLv2 vulnerability.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200612-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All AMD64 x86 emulation base libraries users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-baselibs-2.5.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-baselibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(amd64)$") audit(AUDIT_ARCH_NOT, "amd64", ourarch);

flag = 0;

if (qpkg_check(package:"app-emulation/emul-linux-x86-baselibs", arch:"amd64", unaffected:make_list("ge 2.5.5"), vulnerable:make_list("lt 2.5.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "AMD64 x86 emulation base libraries");
}
