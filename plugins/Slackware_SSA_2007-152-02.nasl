#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2007-152-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25374);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_osvdb_id(35134, 35136, 35137, 35138);
  script_xref(name:"SSA", value:"2007-152-02");

  script_name(english:"Slackware 10.2 / 11.0 / current : firefox-seamonkey-thunderbird (SSA:2007-152-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New mozilla-firefox and seamonkey packages are available for
Slackware 10.2, 11.0, and -current to fix security issues. New
thunderbird packages are are available for Slackware 10.2 and 11.0 to
fix security issues."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3462ca90"
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?637d935f"
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#thunderbird
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7275234"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.571857
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bddd55f5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mozilla-firefox, mozilla-thunderbird and / or
seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"mozilla-firefox", pkgver:"1.5.0.12", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.2", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.12", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"11.0", pkgname:"mozilla-firefox", pkgver:"1.5.0.12", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"11.0", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.12", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"11.0", pkgname:"seamonkey", pkgver:"1.1.2", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla-firefox", pkgver:"2.0.0.4", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey", pkgver:"1.1.2", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
