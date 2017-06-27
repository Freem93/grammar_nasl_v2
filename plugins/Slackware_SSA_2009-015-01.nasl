#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-015-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54871);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/01 00:40:50 $");

  script_xref(name:"SSA", value:"2009-015-01");

  script_name(english:"Slackware 10.2 / 11.0 : bind 10.2/11.0 recompile (SSA:2009-015-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages are available for Slackware 10.2 and 11.0 to
address a load problem. It was reported that the initial build of
these updates complained that the Linux capability module was not
present and would refuse to load. It was determined that the packages
which were compiled on 10.2 and 11.0 systems running 2.6 kernels, and
although the installed kernel headers are from 2.4.x, it picked up on
this resulting in packages that would only run under 2.4 kernels.
These new packages address the issue. As always, any problems noted
with update patches should be reported to security@slackware.com, and
we will do our best to address them as quickly as possible."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.382512
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55c6b5d8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/15");
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
if (slackware_check(osver:"10.2", pkgname:"bind", pkgver:"9.3.6_P1", pkgarch:"i486", pkgnum:"2_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"bind", pkgver:"9.3.6_P1", pkgarch:"i486", pkgnum:"2_slack11.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
