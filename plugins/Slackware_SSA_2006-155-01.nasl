#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-155-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21639);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/19 15:18:22 $");

  script_cve_id("CVE-2006-1516", "CVE-2006-1517", "CVE-2006-2753");
  script_bugtraq_id(17780);
  script_osvdb_id(25226, 25228);
  script_xref(name:"SSA", value:"2006-155-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 9.1 / current : mysql (SSA:2006-155-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New mysql packages are available for Slackware 9.1, 10.0, 10.1, 10.2
and -current to fix security issues. The MySQL packages shipped with
Slackware 9.1, 10.0, and 10.1 may possibly leak sensitive information
found in uninitialized memory to authenticated users. This is fixed in
the new packages, and was already patched in Slackware 10.2 and
-current. Since the vulnerabilities require a valid login and/or
access to the database server, the risk is moderate. Slackware does
not provide network access to a MySQL database by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.mysql.com/announce/364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.mysql.com/announce/365"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.599377
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd83617d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mysql package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"9.1", pkgname:"mysql", pkgver:"4.0.27", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"mysql", pkgver:"4.0.27", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"mysql", pkgver:"4.0.27", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"mysql", pkgver:"4.1.20", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"mysql", pkgver:"5.0.22", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
