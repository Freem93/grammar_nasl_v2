#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2007-053-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24691);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988");
  script_osvdb_id(32762, 32763, 32764, 32765, 32766, 32767, 32776, 34706, 34707, 34708, 34709, 34710, 34711, 34712, 34713, 34714, 34715);
  script_xref(name:"SSA", value:"2007-053-01");

  script_name(english:"Slackware 10.2 / 11.0 : php (SSA:2007-053-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New php packages are available for Slackware 10.2 and 11.0 to improve
the stability and security of PHP. Quite a few bugs were fixed --
please see http://www.php.net for a detailed list. All sites that use
PHP are encouraged to upgrade. Please note that we haven't tested all
PHP applications for backwards compatibility with this new upgrade, so
you should have the old package on hand just in case. Both PHP 4.4.5
and PHP 5.2.1 updates have been provided. Some of these issues have
been assigned CVE numbers and may be referenced in the Common
Vulnerabilities and Exposures (CVE) database:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0906
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0907
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0908
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0909
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0910
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.535756
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ec7ea49"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"10.2", pkgname:"php", pkgver:"4.4.5", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"php", pkgver:"4.4.5", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
