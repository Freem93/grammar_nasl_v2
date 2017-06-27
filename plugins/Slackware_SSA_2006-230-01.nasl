#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-230-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22236);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/09/26 13:31:37 $");

  script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
  script_bugtraq_id(19287);
  script_osvdb_id(27723, 27724, 27725, 27726, 27727, 27728, 27729);
  script_xref(name:"SSA", value:"2006-230-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 9.0 / 9.1 / current : libtiff (SSA:2006-230-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New libtiff packages are available for Slackware 9.0, 9.1, 10.0,
10.1, 10.2, and -current to fix security issues. These issues could be
used to crash programs linked to libtiff or possibly to execute code
as the program's user. Thanks to Tavis Ormandy and the Google Security
Team."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.536600
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27722a90"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iOS MobileMail LibTIFF Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/02");
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
if (slackware_check(osver:"9.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i386", pkgnum:"1_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
