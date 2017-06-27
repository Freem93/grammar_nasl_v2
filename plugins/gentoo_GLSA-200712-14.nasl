#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200712-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(29734);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 14:04:24 $");

  script_cve_id("CVE-2007-4045", "CVE-2007-5849", "CVE-2007-6358");
  script_osvdb_id(40719, 42029, 58777);
  script_xref(name:"GLSA", value:"200712-14");

  script_name(english:"GLSA-200712-14 : CUPS: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200712-14
(CUPS: Multiple vulnerabilities)

    Wei Wang (McAfee AVERT Research) discovered an integer underflow in the
    asn1_get_string() function of the SNMP backend, leading to a
    stack-based buffer overflow when handling SNMP responses
    (CVE-2007-5849). Elias Pipping (Gentoo) discovered that the alternate
    pdftops filter creates temporary files with predictable file names when
    reading from standard input (CVE-2007-6358). Furthermore, the
    resolution of a Denial of Service vulnerability covered in GLSA
    200703-28 introduced another Denial of Service vulnerability within SSL
    handling (CVE-2007-4045).
  
Impact :

    A remote attacker on the local network could exploit the first
    vulnerability to execute arbitrary code with elevated privileges by
    sending specially crafted SNMP messages as a response to an SNMP
    broadcast request. A local attacker could exploit the second
    vulnerability to overwrite arbitrary files with the privileges of the
    user running the CUPS spooler (usually lp) by using symlink attacks. A
    remote attacker could cause a Denial of Service condition via the third
    vulnerability when SSL is enabled in CUPS.
  
Workaround :

    To disable SNMP support in CUPS, you have have to manually delete the
    file '/usr/libexec/cups/backend/snmp'. Please note that the file is
    reinstalled if you merge CUPS again later. To disable the pdftops
    filter, delete all lines referencing 'pdftops' in CUPS' 'mime.convs'
    configuration file. To work around the third vulnerability, disable SSL
    support via the corresponding USE flag."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200703-28.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200712-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-print/cups-1.2.12-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-print/cups", unaffected:make_list("rge 1.2.12-r4", "ge 1.3.5"), vulnerable:make_list("lt 1.3.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CUPS");
}
