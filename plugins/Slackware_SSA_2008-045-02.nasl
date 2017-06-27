#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2008-045-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31100);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2007-3847", "CVE-2007-5000", "CVE-2007-6388");
  script_bugtraq_id(25489, 26838, 27237);
  script_osvdb_id(37051, 39133, 39134, 40262);
  script_xref(name:"SSA", value:"2008-045-02");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 8.1 / 9.0 / 9.1 : apache (SSA:2008-045-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New apache 1.3.41 packages are available for Slackware 8.1, 9.0, 9.1,
10.0, 10.1, 10.2, and 11.0 to fix security issues. A new matching
mod_ssl package is also provided."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.595748
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da8aba8e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache and / or mod_ssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"apache", pkgver:"1.3.41", pkgarch:"i386", pkgnum:"1_slack8.1")) flag++;
if (slackware_check(osver:"8.1", pkgname:"mod_ssl", pkgver:"2.8.31_1.3.41", pkgarch:"i386", pkgnum:"1_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"apache", pkgver:"1.3.41", pkgarch:"i386", pkgnum:"1_slack9.0")) flag++;
if (slackware_check(osver:"9.0", pkgname:"mod_ssl", pkgver:"2.8.31_1.3.41", pkgarch:"i386", pkgnum:"1_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"apache", pkgver:"1.3.41", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"mod_ssl", pkgver:"2.8.31_1.3.41", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"apache", pkgver:"1.3.41", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mod_ssl", pkgver:"2.8.31_1.3.41", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"apache", pkgver:"1.3.41", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"mod_ssl", pkgver:"2.8.31_1.3.41", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"apache", pkgver:"1.3.41", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"mod_ssl", pkgver:"2.8.31_1.3.41", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"apache", pkgver:"1.3.41", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;
if (slackware_check(osver:"11.0", pkgname:"mod_ssl", pkgver:"2.8.31_1.3.41", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
