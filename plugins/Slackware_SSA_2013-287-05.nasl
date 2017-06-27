#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2013-287-05. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70441);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/15 17:36:19 $");

  script_cve_id("CVE-2013-4396");
  script_bugtraq_id(62892);
  script_xref(name:"SSA", value:"2013-287-05");

  script_name(english:"Slackware 12.1 / 12.2 / 13.0 / 13.1 / 13.37 / 14.0 / current : xorg-server (SSA:2013-287-05)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New xorg-server packages are available for Slackware 12.1, 12.2,
13.0, 13.1, 13.37, 14.0, and -current to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.1093476
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea198e54"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/15");
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
if (slackware_check(osver:"12.1", pkgname:"xorg-server", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"3_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"xorg-server-xnest", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"3_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"xorg-server-xvfb", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"3_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"xorg-server", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"3_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"xorg-server-xnest", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"3_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"xorg-server-xvfb", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"3_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"xorg-server", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"3_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xorg-server-xephyr", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"3_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xorg-server-xnest", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"3_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xorg-server-xvfb", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"3_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"3_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"3_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"3_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"3_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"xorg-server", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"3_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xorg-server-xephyr", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"3_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xorg-server-xnest", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"3_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xorg-server-xvfb", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"3_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"3_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"3_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"3_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"3_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"xorg-server", pkgver:"1.9.5", pkgarch:"i486", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"xorg-server-xephyr", pkgver:"1.9.5", pkgarch:"i486", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"xorg-server-xnest", pkgver:"1.9.5", pkgarch:"i486", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"xorg-server-xvfb", pkgver:"1.9.5", pkgarch:"i486", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.9.5", pkgarch:"x86_64", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.9.5", pkgarch:"x86_64", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.9.5", pkgarch:"x86_64", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.9.5", pkgarch:"x86_64", pkgnum:"3_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"xorg-server", pkgver:"1.12.4", pkgarch:"i486", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"xorg-server-xephyr", pkgver:"1.12.4", pkgarch:"i486", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"xorg-server-xnest", pkgver:"1.12.4", pkgarch:"i486", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"xorg-server-xvfb", pkgver:"1.12.4", pkgarch:"i486", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.12.4", pkgarch:"x86_64", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.12.4", pkgarch:"x86_64", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.12.4", pkgarch:"x86_64", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.12.4", pkgarch:"x86_64", pkgnum:"2_slack14.0")) flag++;

if (slackware_check(osver:"current", pkgname:"xorg-server", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xephyr", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xnest", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xvfb", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
