#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-114-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21272);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_osvdb_id(22890, 22891, 22892, 22893, 22894, 22895, 22896, 22897, 22898, 22899);
  script_xref(name:"SSA", value:"2006-114-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / current : mozilla security/EOL (SSA:2006-114-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Mozilla packages are available for Slackware 10.0, 10.1, 10.2 and
-current to fix multiple security issues."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5914c79b"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.505446
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b95dccf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla and / or mozilla-plugins packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox location.QueryInterface() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.0", pkgname:"mozilla", pkgver:"1.7.13", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mozilla-plugins", pkgver:"1.7.13", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.1", pkgname:"mozilla", pkgver:"1.7.13", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"mozilla-plugins", pkgver:"1.7.13", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"mozilla", pkgver:"1.7.13", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla", pkgver:"1.7.13", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
