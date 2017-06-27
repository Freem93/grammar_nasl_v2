#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2004-223-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18794);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/11/14 18:42:59 $");

  script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2004-0718", "CVE-2004-0722", "CVE-2004-0757", "CVE-2004-0758", "CVE-2004-0759", "CVE-2004-0760", "CVE-2004-0761", "CVE-2004-0762", "CVE-2004-0763", "CVE-2004-0764", "CVE-2004-0765");
  script_xref(name:"SSA", value:"2004-223-01");

  script_name(english:"Slackware 10.0 / 9.1 / current : Mozilla (SSA:2004-223-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Mozilla packages are available for Slackware 9.1, 10.0, and
-current to fix a number of security issues. Slackware 10.0 and
-current were upgraded to Mozilla 1.7.2, and Slackware 9.1 was
upgraded to Mozilla 1.4.3. As usual, new versions of Mozilla require
new versions of things that link with the Mozilla libraries, so for
Slackware 10.0 and -current new versions of epiphany, galeon, gaim,
and mozilla-plugins have also been provided. There don't appear to be
epiphany and galeon versions that are compatible with Mozilla 1.4.3
and the GNOME in Slackware 9.1, so these are not provided and Epiphany
and Galeon will be broken on Slackware 9.1 if the new Mozilla package
is installed. Furthermore, earlier versions of Mozilla (such as the
1.3 series) were not fixed upstream, so versions of Slackware earlier
than 9.1 will remain vulnerable to these browser issues. If you still
use Slackware 9.0 or earlier, you may want to consider removing
Mozilla or upgrading to a newer version."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.667659
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38dd43e4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
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
if (slackware_check(osver:"9.1", pkgname:"mozilla", pkgver:"1.4.3", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"mozilla-plugins", pkgver:"1.4.3", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"epiphany", pkgver:"1.2.7", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"gaim", pkgver:"0.81", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"galeon", pkgver:"1.3.17", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mozilla", pkgver:"1.7.2", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mozilla-plugins", pkgver:"1.7.2", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"epiphany", pkgver:"1.2.7", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"gaim", pkgver:"0.81", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"galeon", pkgver:"1.3.17", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mozilla", pkgver:"1.7.2", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mozilla-plugins", pkgver:"1.7.2", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
