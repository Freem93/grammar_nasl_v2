#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-111-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36186);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2009-1185", "CVE-2009-1186");
  script_bugtraq_id(34536, 34539);
  script_osvdb_id(53810, 53811);
  script_xref(name:"SSA", value:"2009-111-01");

  script_name(english:"Slackware 10.2 / 11.0 / 12.0 / 12.1 / 12.2 / current : udev (SSA:2009-111-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New udev packages are available for Slackware 10.2, 11.0, 12.0, 12.1,
12.2, and -current to fix security issues. The udev packages in
Slackware 10.2, 11.0, 12.0, 12.1, 12.2, and -current contained a local
root hole vulnerability:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1185 The udev
packages in Slackware 12.0, 12.1, 12.2, and -current had an integer
overflow which could result in a denial of service:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1186 Note that
udev is only used with 2.6 kernels, which are not used by default with
Slackware 10.2 and 11.0."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.446399
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42006a3b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected udev package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux udev Netlink Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"udev", pkgver:"064", pkgarch:"i486", pkgnum:"4_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"udev", pkgver:"097", pkgarch:"i486", pkgnum:"11_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"udev", pkgver:"111", pkgarch:"i486", pkgnum:"6_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"udev", pkgver:"118", pkgarch:"i486", pkgnum:"4_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"udev", pkgver:"141", pkgarch:"i486", pkgnum:"1_slack12.2")) flag++;

if (slackware_check(osver:"current", pkgname:"udev", pkgver:"141", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
