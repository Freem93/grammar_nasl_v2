#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-242-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19859);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2005-2491", "CVE-2005-2498");
  script_osvdb_id(18889, 18906);
  script_xref(name:"SSA", value:"2005-242-02");

  script_name(english:"Slackware 10.0 / 10.1 / 8.1 / 9.0 / 9.1 / current : PHP (SSA:2005-242-02)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New PHP packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, and -current to fix security issues. PHP has been relinked with
the shared PCRE library to fix an overflow issue with PHP's builtin
PRCE code, and PEAR::XMLRPC has been upgraded to version 1.4.0 which
eliminates the eval() function. The eval() function is believed to be
insecure as implemented, and would be difficult to secure. Note that
these new packages now require that the PCRE package be installed, so
be sure to get the new package from the patches/packages/ directory if
you don't already have it. A new version of this (6.3) was also issued
today, so be sure that is the one you install."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.481382
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f72b2a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"php", pkgver:"4.3.11", pkgarch:"i386", pkgnum:"4")) flag++;

if (slackware_check(osver:"9.0", pkgname:"php", pkgver:"4.3.11", pkgarch:"i386", pkgnum:"4")) flag++;

if (slackware_check(osver:"9.1", pkgname:"php", pkgver:"4.3.11", pkgarch:"i486", pkgnum:"4")) flag++;

if (slackware_check(osver:"10.0", pkgname:"php", pkgver:"4.3.11", pkgarch:"i486", pkgnum:"3")) flag++;

if (slackware_check(osver:"10.1", pkgname:"php", pkgver:"4.3.11", pkgarch:"i486", pkgnum:"3")) flag++;

if (slackware_check(osver:"current", pkgname:"php", pkgver:"4.4.0", pkgarch:"i486", pkgnum:"3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
