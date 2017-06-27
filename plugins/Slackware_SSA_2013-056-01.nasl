#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2013-056-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64879);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/19 14:44:43 $");

  script_bugtraq_id(58034, 58036, 58037, 58038, 58040, 58041, 58042, 58043, 58044, 58047, 58048, 58049, 58050, 58051);
  script_xref(name:"SSA", value:"2013-056-01");

  script_name(english:"Slackware 13.37 / 14.0 / current : seamonkey (SSA:2013-056-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New seamonkey packages are available for Slackware 13.37, 14.0, and
-current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.493597
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb86c253"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey and / or seamonkey-solibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.37", pkgname:"seamonkey", pkgver:"2.16", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"seamonkey-solibs", pkgver:"2.16", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"seamonkey", pkgver:"2.16", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"seamonkey-solibs", pkgver:"2.16", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"seamonkey", pkgver:"2.16", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"seamonkey-solibs", pkgver:"2.16", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"seamonkey", pkgver:"2.16", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"seamonkey-solibs", pkgver:"2.16", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;

if (slackware_check(osver:"current", pkgname:"seamonkey", pkgver:"2.16", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey-solibs", pkgver:"2.16", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"seamonkey", pkgver:"2.16", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"seamonkey-solibs", pkgver:"2.16", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
