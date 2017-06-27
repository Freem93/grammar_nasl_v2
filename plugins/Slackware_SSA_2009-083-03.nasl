#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-083-03. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36011);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776");
  script_bugtraq_id(33598, 33990);
  script_osvdb_id(51929, 51931, 51932, 51933, 51934, 51935, 51936, 51937, 51938, 51939, 51940, 52444, 52445, 52446, 52447, 52448, 52449, 52451, 53315, 53316, 53317);
  script_xref(name:"SSA", value:"2009-083-03");

  script_name(english:"Slackware 10.2 / 11.0 / 12.0 / 12.1 / 12.2 / current : mozilla-thunderbird (SSA:2009-083-03)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New mozilla-thunderbird packages are available for Slackware 10.2,
11.0, 12.0, 12.1, 12.2, and -current to fix security issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?280be806"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.433952
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe11b3e0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/25");
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
if (slackware_check(osver:"10.2", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.21", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"11.0", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.21", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"12.0", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.21", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"12.1", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.21", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.21", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.21", pkgarch:"i686", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
