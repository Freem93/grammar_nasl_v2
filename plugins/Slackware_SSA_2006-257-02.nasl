#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-257-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22348);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/02/17 15:06:27 $");

  script_cve_id("CVE-2006-4339");
  script_osvdb_id(28549);
  script_xref(name:"SSA", value:"2006-257-02");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 8.1 / 9.0 / 9.1 / current : openssl (SSA:2006-257-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New openssl packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, 10.2, and -current to fix a signature forgery security issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20060905.txt"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.605306
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf74f425"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl and / or openssl-solibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"openssl", pkgver:"0.9.6m", pkgarch:"i386", pkgnum:"3_slack8.1")) flag++;
if (slackware_check(osver:"8.1", pkgname:"openssl-solibs", pkgver:"0.9.6m", pkgarch:"i386", pkgnum:"3_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"openssl", pkgver:"0.9.7d", pkgarch:"i386", pkgnum:"3_slack9.0")) flag++;
if (slackware_check(osver:"9.0", pkgname:"openssl-solibs", pkgver:"0.9.7d", pkgarch:"i386", pkgnum:"3_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"openssl", pkgver:"0.9.7d", pkgarch:"i486", pkgnum:"3_slack9.1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"openssl-solibs", pkgver:"0.9.7d", pkgarch:"i486", pkgnum:"3_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"openssl", pkgver:"0.9.7d", pkgarch:"i486", pkgnum:"3_slack10.0")) flag++;
if (slackware_check(osver:"10.0", pkgname:"openssl-solibs", pkgver:"0.9.7d", pkgarch:"i486", pkgnum:"3_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"openssl", pkgver:"0.9.7e", pkgarch:"i486", pkgnum:"5_slack10.1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"openssl-solibs", pkgver:"0.9.7e", pkgarch:"i486", pkgnum:"5_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"openssl", pkgver:"0.9.7g", pkgarch:"i486", pkgnum:"3_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"openssl-solibs", pkgver:"0.9.7g", pkgarch:"i486", pkgnum:"3_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"openssl", pkgver:"0.9.8b", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"openssl-solibs", pkgver:"0.9.8b", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
