#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2008-210-08. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33753);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2008-0891", "CVE-2008-1672");
  script_bugtraq_id(29405);
  script_osvdb_id(45660, 45661);
  script_xref(name:"SSA", value:"2008-210-08");

  script_name(english:"Slackware 11.0 / 12.0 / 12.1 / current : openssl (SSA:2008-210-08)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New openssl packages are available for Slackware 11.0, 12.0, 12.1,
and -current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.562004
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a52e1366"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh, openssl and / or openssl-solibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/29");
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
if (slackware_check(osver:"11.0", pkgname:"openssh", pkgver:"5.1p1", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;
if (slackware_check(osver:"11.0", pkgname:"openssl", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;
if (slackware_check(osver:"11.0", pkgname:"openssl-solibs", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"openssh", pkgver:"5.1p1", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"openssl", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"openssl-solibs", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"openssh", pkgver:"5.1p1", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"openssl", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"openssl-solibs", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;

if (slackware_check(osver:"current", pkgname:"openssh", pkgver:"5.1p1", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"openssl", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"openssl-solibs", pkgver:"0.9.8h", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
