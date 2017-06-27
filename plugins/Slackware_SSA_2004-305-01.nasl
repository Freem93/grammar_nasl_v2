#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2004-305-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18788);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_cve_id("CVE-2004-0940");
  script_osvdb_id(11003);
  script_xref(name:"SSA", value:"2004-305-01");

  script_name(english:"Slackware 10.0 / 8.1 / 9.0 / 9.1 / current : apache+mod_ssl (SSA:2004-305-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
and -current to fix a security issue. Apache has been upgraded to
version 1.3.33 which fixes a buffer overflow which may allow local
users to execute arbitrary code as the apache user. The mod_ssl
package has also been upgraded to version 2.8.22_1.3.33."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.533785
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbba9317"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache and / or mod_ssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/21");
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
if (slackware_check(osver:"8.1", pkgname:"apache", pkgver:"1.3.33", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"8.1", pkgname:"mod_ssl", pkgver:"2.8.22_1.3.33", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"apache", pkgver:"1.3.33", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"mod_ssl", pkgver:"2.8.22_1.3.33", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.1", pkgname:"apache", pkgver:"1.3.33", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"mod_ssl", pkgver:"2.8.22_1.3.33", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"apache", pkgver:"1.3.33", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mod_ssl", pkgver:"2.8.22_1.3.33", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"apache", pkgver:"1.3.33", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mod_ssl", pkgver:"2.8.22_1.3.33", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
