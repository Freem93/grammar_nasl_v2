#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2007-152-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25373);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_cve_id("CVE-2007-1900", "CVE-2007-2756", "CVE-2007-2872");
  script_osvdb_id(33962, 35788, 36083, 36643);
  script_xref(name:"SSA", value:"2007-152-01");

  script_name(english:"Slackware 10.2 / 11.0 / current : php5 (SSA:2007-152-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New php5 packages are available for Slackware 10.2, 11.0, and
-current to fix security issues. PHP5 was considered a test package in
Slackware 10.2, and an 'extra' package in Slackware 11.0. If you are
currently running PHP4 you may wish to stick with that, as upgrading
to PHP5 will probably require changes to your system's configuration
and/or web code."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.482863
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1911273"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"php", pkgver:"5.2.3", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"php", pkgver:"5.2.3", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"current", pkgname:"php", pkgver:"5.2.3", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
