#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2010-301-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50388);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:46:31 $");

  script_cve_id("CVE-2010-3856");
  script_bugtraq_id(44347);
  script_xref(name:"SSA", value:"2010-301-01");

  script_name(english:"Slackware 12.0 / 12.1 / 12.2 / 13.0 / 13.1 / current : glibc (SSA:2010-301-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New glibc packages are available for Slackware 12.0, 12.1, 12.2,
13.0, 13.1, and -current to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.1054477
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35456feb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-solibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-zoneinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"12.0", pkgname:"glibc", pkgver:"2.5", pkgarch:"i486", pkgnum:"6_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"glibc-i18n", pkgver:"2.5", pkgarch:"noarch", pkgnum:"6_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"glibc-profile", pkgver:"2.5", pkgarch:"i486", pkgnum:"6_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"glibc-solibs", pkgver:"2.5", pkgarch:"i486", pkgnum:"6_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"glibc-zoneinfo", pkgver:"2.5", pkgarch:"noarch", pkgnum:"9_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"glibc", pkgver:"2.7", pkgarch:"i486", pkgnum:"12_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"glibc-i18n", pkgver:"2.7", pkgarch:"noarch", pkgnum:"12_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"glibc-profile", pkgver:"2.7", pkgarch:"i486", pkgnum:"12_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"glibc-solibs", pkgver:"2.7", pkgarch:"i486", pkgnum:"12_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"glibc-zoneinfo", pkgver:"2.7", pkgarch:"noarch", pkgnum:"12_slack12.0")) flag++;

if (slackware_check(osver:"12.2", pkgname:"glibc", pkgver:"2.7", pkgarch:"i486", pkgnum:"19_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"glibc-i18n", pkgver:"2.7", pkgarch:"noarch", pkgnum:"19_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"glibc-profile", pkgver:"2.7", pkgarch:"i486", pkgnum:"19_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"glibc-solibs", pkgver:"2.7", pkgarch:"i486", pkgnum:"19_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"glibc-zoneinfo", pkgver:"2.7", pkgarch:"noarch", pkgnum:"19_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"glibc", pkgver:"2.9", pkgarch:"i486", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-i18n", pkgver:"2.9", pkgarch:"i486", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-profile", pkgver:"2.9", pkgarch:"i486", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-solibs", pkgver:"2.9", pkgarch:"i486", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-zoneinfo", pkgver:"2.9", pkgarch:"noarch", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2.9", pkgarch:"noarch", pkgnum:"5_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"glibc", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-i18n", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-profile", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-solibs", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-zoneinfo", pkgver:"2.11.1", pkgarch:"noarch", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"5_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2.11.1", pkgarch:"noarch", pkgnum:"5_slack13.1")) flag++;

if (slackware_check(osver:"current", pkgname:"glibc", pkgver:"2.12.1", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-i18n", pkgver:"2.12.1", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-profile", pkgver:"2.12.1", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-solibs", pkgver:"2.12.1", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-zoneinfo", pkgver:"2.12.1", pkgarch:"noarch", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc", pkgver:"2.12.1", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.12.1", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.12.1", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.12.1", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2.12.1", pkgarch:"noarch", pkgnum:"3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
