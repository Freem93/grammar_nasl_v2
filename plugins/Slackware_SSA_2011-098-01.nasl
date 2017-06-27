#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2011-098-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53362);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/12 14:46:31 $");

  script_cve_id("CVE-2011-0192", "CVE-2011-1167");
  script_bugtraq_id(46658, 46951);
  script_osvdb_id(71256, 71257);
  script_xref(name:"SSA", value:"2011-098-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 12.0 / 12.1 / 12.2 / 13.0 / 13.1 / 9.0 / 9.1 / current : libtiff (SSA:2011-098-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New libtiff packages are available for Slackware 9.0, 9.1, 10.0,
10.1, 10.2, 11.0, 12.0, 12.1, 12.2, 13.0, 13.1, and -current to fix
security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2011&m=slackware-security.587820
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f216d76"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"9.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i386", pkgnum:"3_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"3_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"3_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"3_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"3_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"4_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"5_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"5_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"5_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"x86_64", pkgnum:"5_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"libtiff", pkgver:"3.9.4", pkgarch:"i486", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libtiff", pkgver:"3.9.4", pkgarch:"x86_64", pkgnum:"2_slack13.1")) flag++;

if (slackware_check(osver:"current", pkgname:"libtiff", pkgver:"3.9.4", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libtiff", pkgver:"3.9.4", pkgarch:"x86_64", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
