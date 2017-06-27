#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2013-260-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69935);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/03 12:36:16 $");

  script_cve_id("CVE-2013-2013");
  script_bugtraq_id(62324);
  script_xref(name:"SSA", value:"2013-260-01");

  script_name(english:"Slackware 13.0 / 13.1 / 13.37 / 14.0 / current : glibc (SSA:2013-260-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New glibc packages are available for Slackware 13.0, 13.1, 13.37,
14.0, and -current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.1106410
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0785259"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-solibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-zoneinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.0", pkgname:"glibc", pkgver:"2.9", pkgarch:"i486", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-i18n", pkgver:"2.9", pkgarch:"i486", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-profile", pkgver:"2.9", pkgarch:"i486", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-solibs", pkgver:"2.9", pkgarch:"i486", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"6_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"glibc", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-i18n", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-profile", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-solibs", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"8_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"8_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"glibc", pkgver:"2.13", pkgarch:"i486", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-i18n", pkgver:"2.13", pkgarch:"i486", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-profile", pkgver:"2.13", pkgarch:"i486", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-solibs", pkgver:"2.13", pkgarch:"i486", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"7_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"7_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"glibc", pkgver:"2.15", pkgarch:"i486", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-i18n", pkgver:"2.15", pkgarch:"i486", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-profile", pkgver:"2.15", pkgarch:"i486", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-solibs", pkgver:"2.15", pkgarch:"i486", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-zoneinfo", pkgver:"2013d_2013d", pkgarch:"noarch", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"8_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2013d_2013d", pkgarch:"noarch", pkgnum:"8_slack14.0")) flag++;

if (slackware_check(osver:"current", pkgname:"glibc", pkgver:"2.17", pkgarch:"i486", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-i18n", pkgver:"2.17", pkgarch:"i486", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-profile", pkgver:"2.17", pkgarch:"i486", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-solibs", pkgver:"2.17", pkgarch:"i486", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"7")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2013d", pkgarch:"noarch", pkgnum:"7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:slackware_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
