#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2016-305-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94439);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/01 16:04:34 $");

  script_xref(name:"SSA", value:"2016-305-02");

  script_name(english:"Slackware 13.0 / 13.1 / 13.37 / 14.0 / 14.1 / 14.2 / current : x11 (SSA:2016-305-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New x11 packages are available for Slackware 13.0, 13.1, 13.37, 14.0,
14.1, 14.2, and -current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.3362343
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e801ee13"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:fixesproto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:inputproto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:randrproto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:recordproto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xextproto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xproto");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.0", pkgname:"fixesproto", pkgver:"5.0", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"recordproto", pkgver:"1.14.2", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"fixesproto", pkgver:"5.0", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"recordproto", pkgver:"1.14.2", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"fixesproto", pkgver:"5.0", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"recordproto", pkgver:"1.14.2", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"fixesproto", pkgver:"5.0", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"recordproto", pkgver:"1.14.2", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"recordproto", pkgver:"1.14.2", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"recordproto", pkgver:"1.14.2", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack14.0")) flag++;

if (slackware_check(osver:"14.1", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"inputproto", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXext", pkgver:"1.3.3", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libxcb", pkgver:"1.11.1", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"randrproto", pkgver:"1.5.0", pkgarch:"noarch", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"xcb-proto", pkgver:"1.11", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"xextproto", pkgver:"7.3.0", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"xproto", pkgver:"7.0.29", pkgarch:"noarch", pkgnum:"1_slack14.1")) flag++;

if (slackware_check(osver:"14.2", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;

if (slackware_check(osver:"current", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libX11", pkgver:"1.6.4", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libXfixes", pkgver:"5.0.3", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libXi", pkgver:"1.7.8", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libXrandr", pkgver:"1.5.1", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libXrender", pkgver:"0.9.10", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libXtst", pkgver:"1.2.3", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libXv", pkgver:"1.0.11", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libXvMC", pkgver:"1.0.10", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
