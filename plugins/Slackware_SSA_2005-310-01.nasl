#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-310-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20149);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:36:13 $");

  script_cve_id("CVE-2005-3185");
  script_osvdb_id(20011, 20012);
  script_xref(name:"SSA", value:"2005-310-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 8.1 / 9.0 / 9.1 / current : curl/wget (SSA:2005-310-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New curl packages are available for Slackware 9.1, 10.0, 10.1, 10.2,
and -current, and new wget packages are available for Slackware 8.1,
9.0, 9.1, 10.0, 10.1, 10.2, and -current. These address a buffer
overflow in NTLM handling which may present a security problem, though
no public exploits are known at this time."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.519010
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?642e50a1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected curl and / or wget packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/13");
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
if (slackware_check(osver:"8.1", pkgname:"wget", pkgver:"1.10.2", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"wget", pkgver:"1.10.2", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.1", pkgname:"curl", pkgver:"7.10.7", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"9.1", pkgname:"wget", pkgver:"1.10.2", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"curl", pkgver:"7.12.2", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"10.0", pkgname:"wget", pkgver:"1.10.2", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.1", pkgname:"curl", pkgver:"7.12.2", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"10.1", pkgname:"wget", pkgver:"1.10.2", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"curl", pkgver:"7.12.2", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"wget", pkgver:"1.10.2", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"curl", pkgver:"7.12.2", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"wget", pkgver:"1.10.2", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");