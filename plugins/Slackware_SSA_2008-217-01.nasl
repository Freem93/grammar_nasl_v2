#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2008-217-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33824);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2008-1679", "CVE-2008-1721", "CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3144");
  script_bugtraq_id(28715, 30491);
  script_osvdb_id(44463, 44693, 47478, 47479, 47480, 47481);
  script_xref(name:"SSA", value:"2008-217-01");

  script_name(english:"Slackware 10.1 / 10.2 / 11.0 / 12.0 / 12.1 / current : python (SSA:2008-217-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New python packages are available for Slackware 10.1, 10.2, 11.0,
12.0, 12.1, and -current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.525289
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41912d97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected python, python-demo and / or python-tools
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.1", pkgname:"python", pkgver:"2.4.5", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"python-demo", pkgver:"2.4.5", pkgarch:"noarch", pkgnum:"1_slack10.1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"python-tools", pkgver:"2.4.5", pkgarch:"noarch", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"python", pkgver:"2.4.5", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"python-demo", pkgver:"2.4.5", pkgarch:"noarch", pkgnum:"1_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"python-tools", pkgver:"2.4.5", pkgarch:"noarch", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"python", pkgver:"2.4.5", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"python", pkgver:"2.5.2", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"python", pkgver:"2.5.2", pkgarch:"i486", pkgnum:"2_slack12.1")) flag++;

if (slackware_check(osver:"current", pkgname:"python", pkgver:"2.5.2", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
