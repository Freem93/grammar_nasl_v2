#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2011-252-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56142);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id("CVE-2011-3192");
  script_bugtraq_id(49303);
  script_xref(name:"SSA", value:"2011-252-01");

  script_name(english:"Slackware 12.0 / 12.1 / 12.2 / 13.0 / 13.1 / 13.37 / current : httpd (SSA:2011-252-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Not long ago, httpd package updates were issued to clamp down on a
denial of service bug that's seen some action in the wild. New
packages are available for Slackware 12.0, 12.1, 12.2, 13.0, 13.1,
13.37, and -current."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2011&m=slackware-security.509101
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18a82f11"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected httpd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");
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
if (slackware_check(osver:"12.0", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"i486", pkgnum:"1_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;

if (slackware_check(osver:"current", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.20", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
