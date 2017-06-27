#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-25.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56659);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2011-0418", "CVE-2011-1575");
  script_bugtraq_id(46767, 47671);
  script_osvdb_id(71855, 72176, 89994, 90005);
  script_xref(name:"GLSA", value:"201110-25");

  script_name(english:"GLSA-201110-25 : Pure-FTPd: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-25
(Pure-FTPd: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Pure-FTPd. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    Remote unauthenticated attackers may be able to inject FTP commands or
      cause a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All pure-ftpd users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-ftp/pure-ftpd-1.0.32'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since May 14, 2011. It is likely that your system is already no
      longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pure-ftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/27");
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

if (qpkg_check(package:"net-ftp/pure-ftpd", unaffected:make_list("ge 1.0.32"), vulnerable:make_list("lt 1.0.32"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Pure-FTPd");
}
