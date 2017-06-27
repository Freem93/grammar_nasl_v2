#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2004-296-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18760);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_cve_id("CVE-2004-0891");
  script_osvdb_id(10986);
  script_xref(name:"SSA", value:"2004-296-01");

  script_name(english:"Slackware 10.0 / 9.0 / 9.1 / current : gaim (SSA:2004-296-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New gaim packages are available for Slackware 9.0, 9.1, 10.0 and
-current to fix a buffer overflow in the MSN protocol. Sites that use
GAIM should upgrade to the new version."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.376183
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10a891bc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"9.0", pkgname:"gaim", pkgver:"1.0.2", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.1", pkgname:"gaim", pkgver:"1.0.2", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"gaim", pkgver:"1.0.2", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"gaim", pkgver:"1.0.2", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
