#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the associated Slackware Security Advisory. The
# text itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54860);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/01 00:44:11 $");

  script_name(english:"Slackware 9.0 : Updated KDE packages available");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New KDE 3.1.1a packages are available for Slackware 9.0 which fix a
security problem with the handling of PS and PDF documents."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.436331
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd373b16"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdeaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdeadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdebindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdevelop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:quanta");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"9.0", pkgname:"arts", pkgver:"1.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdeaddons", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdeadmin", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdeartwork", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdebase", pkgver:"3.1.1a", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdebindings", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdeedu", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdegames", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdegraphics", pkgver:"3.1.1a", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdelibs", pkgver:"3.1.1a", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdemultimedia", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdenetwork", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdepim", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdesdk", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdetoys", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdeutils", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kdevelop", pkgver:"3.0a4a", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"koffice", pkgver:"1.2.1", pkgarch:"i386", pkgnum:"3")) flag++;
if (slackware_check(osver:"9.0", pkgname:"qt", pkgver:"3.1.2", pkgarch:"i386", pkgnum:"3")) flag++;
if (slackware_check(osver:"9.0", pkgname:"quanta", pkgver:"3.1.1", pkgarch:"i386", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
