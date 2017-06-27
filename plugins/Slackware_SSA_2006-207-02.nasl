#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-207-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22099);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:36:13 $");

  script_cve_id("CVE-2006-1861");
  script_xref(name:"SSA", value:"2006-207-02");

  script_name(english:"Slackware 10.2 / current : x11 (SSA:2006-207-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New x11 packages are available for Slackware 10.2 and -current to fix
security issues. In addition, fontconfig and freetype have been split
out from the x11 packages in -current, so if you run -current you'll
also need to install those new packages."
  );
  # http://lists.freedesktop.org/archives/xorg-announce/2006-June/000100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d68596c"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.549901
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef9a444e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:fontconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"x11", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"6_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-devel", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"6_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xdmx", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"6_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xnest", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"6_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xvfb", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"6_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"fontconfig", pkgver:"2.2.3", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"freetype", pkgver:"2.1.9", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"x11", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-devel", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xdmx", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xnest", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xvfb", pkgver:"6.9.0", pkgarch:"i486", pkgnum:"5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
