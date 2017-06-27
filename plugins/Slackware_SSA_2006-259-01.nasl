#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-259-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22420);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/19 15:18:22 $");

  script_cve_id("CVE-2006-3739", "CVE-2006-3740");
  script_bugtraq_id(19974);
  script_xref(name:"SSA", value:"2006-259-01");

  script_name(english:"Slackware 10.2 / current : x11 (SSA:2006-259-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New x11 (X.Org) packages are available for Slackware 10.2, and
-current to fix security issues due to overflows in font parsing."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.522407
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d183a93e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"x11", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"7_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-devel", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"7_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xdmx", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"7_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xnest", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"7_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xvfb", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"7_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"x11", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"11")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-devel", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"11")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xdmx", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"11")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xnest", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"11")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xvfb", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
