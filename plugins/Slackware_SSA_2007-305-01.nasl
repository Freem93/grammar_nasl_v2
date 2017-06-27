#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2007-305-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27609);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/01 00:36:14 $");

  script_cve_id("CVE-2007-4351");
  script_osvdb_id(42028);
  script_xref(name:"SSA", value:"2007-305-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 12.0 / 8.1 / 9.0 / 9.1 / current : cups (SSA:2007-305-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CUPS was found to contain errors in ipp.c which could allow a remote
attacker to crash CUPS, resulting in a denial of service. If you use
CUPS, it is recommended to update to the latest package for your
version of Slackware. The latest cups package is available for
Slackware -current, and patched packages are available for Slackware
8.1, 9.0, 9.1, 10.0, 10.1, 10.2, 11.0, and 12.0 that fix the problems."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.501902
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2edf5e4b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"cups", pkgver:"1.1.19", pkgarch:"i386", pkgnum:"2_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"cups", pkgver:"1.1.19", pkgarch:"i386", pkgnum:"2_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"cups", pkgver:"1.1.21", pkgarch:"i486", pkgnum:"2_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"cups", pkgver:"1.1.21", pkgarch:"i486", pkgnum:"2_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"cups", pkgver:"1.1.23", pkgarch:"i486", pkgnum:"2_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"cups", pkgver:"1.1.23", pkgarch:"i486", pkgnum:"2_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"cups", pkgver:"1.1.23", pkgarch:"i486", pkgnum:"5_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"cups", pkgver:"1.2.11", pkgarch:"i486", pkgnum:"2_slack12.0")) flag++;

if (slackware_check(osver:"current", pkgname:"cups", pkgver:"1.3.3", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
