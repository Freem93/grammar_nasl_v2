#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201309-15.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70111);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-3867", "CVE-2010-4221", "CVE-2010-4652", "CVE-2011-1137", "CVE-2011-4130", "CVE-2012-6095", "CVE-2013-4359");
  script_bugtraq_id(36935, 44562, 44933, 46183, 50631, 57172, 62328);
  script_osvdb_id(68985, 68988, 70782, 70868, 77004, 89051, 97184);
  script_xref(name:"GLSA", value:"201309-15");

  script_name(english:"GLSA-201309-15 : ProFTPD: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201309-15
(ProFTPD: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in ProFTPD. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A context-dependent attacker could possibly execute arbitrary code with
      the privileges of the process, perform man-in-the-middle attacks to spoof
      arbitrary SSL servers, cause a Denial of Service condition, or read and
      modify arbitrary files.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201309-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ProFTPD users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-ftp/proftpd-1.3.4d'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-ftp/proftpd", unaffected:make_list("ge 1.3.4d"), vulnerable:make_list("lt 1.3.4d"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ProFTPD");
}
