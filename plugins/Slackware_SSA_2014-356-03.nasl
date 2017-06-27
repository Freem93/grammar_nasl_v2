#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2014-356-03. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80206);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/29 13:37:05 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2014-8103");
  script_bugtraq_id(71595, 71596, 71597, 71598, 71599, 71600, 71601, 71602, 71603, 71604, 71605, 71606, 71608);
  script_xref(name:"SSA", value:"2014-356-03");

  script_name(english:"Slackware 14.1 / current : xorg-server (SSA:2014-356-03)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New xorg-server packages are available for Slackware 14.1 and
-current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2014&m=slackware-security.618701
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bed9b951"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"14.1", pkgname:"xorg-server", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"xorg-server-xephyr", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"xorg-server-xnest", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"xorg-server-xvfb", pkgver:"1.14.3", pkgarch:"i486", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.14.3", pkgarch:"x86_64", pkgnum:"3_slack14.1")) flag++;

if (slackware_check(osver:"current", pkgname:"xorg-server", pkgver:"1.15.2", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xephyr", pkgver:"1.15.2", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xnest", pkgver:"1.15.2", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xvfb", pkgver:"1.15.2", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.15.2", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.15.2", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.15.2", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.15.2", pkgarch:"x86_64", pkgnum:"3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
