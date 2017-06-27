#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2004-278-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18776);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_cve_id("CVE-2004-0880", "CVE-2004-0881");
  script_osvdb_id(10072);
  script_xref(name:"SSA", value:"2004-278-01");

  script_name(english:"Slackware 10.0 / 9.1 / current : getmail (SSA:2004-278-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New getmail packages are available for Slackware 9.1, 10.0 and
-current to fix a security issue. If getmail is used as root to
deliver to user owned files or directories, it can be made to
overwrite system files."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.417584
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0849bc1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected getmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:getmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/19");
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
if (slackware_check(osver:"9.1", pkgname:"getmail", pkgver:"3.2.5", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"getmail", pkgver:"4.2.0", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"getmail", pkgver:"4.2.0", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:slackware_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
