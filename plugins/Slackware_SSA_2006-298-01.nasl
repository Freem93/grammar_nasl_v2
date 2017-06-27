#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-298-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24657);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/01 00:36:13 $");

  script_cve_id("CVE-2006-4811");
  script_osvdb_id(29843);
  script_xref(name:"SSA", value:"2006-298-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 : qt (SSA:2006-298-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New qt packages are available for Slackware 10.0, 10.1, 10.2, and
11.0 to fix a possible security issue."
  );
  # http://www.trolltech.com/company/newsroom/announcements/press.2006-10-19.5434451733
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f5781fd"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.483634
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5812dc12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qca-tls and / or qt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:qca-tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.0", pkgname:"qt", pkgver:"3.3.3", pkgarch:"i486", pkgnum:"2_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"qt", pkgver:"3.3.3", pkgarch:"i486", pkgnum:"4_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"qt", pkgver:"3.3.4", pkgarch:"i486", pkgnum:"3_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"qca-tls", pkgver:"1.0", pkgarch:"i486", pkgnum:"3_slack11.0")) flag++;
if (slackware_check(osver:"11.0", pkgname:"qt", pkgver:"3.3.7", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
