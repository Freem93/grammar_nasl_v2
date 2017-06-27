#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2008-089-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31706);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/19 14:44:43 $");

  script_bugtraq_id(28448);
  script_osvdb_id(38036, 42601, 43846, 43847, 43848, 43849, 43857, 43858, 43859, 43860, 43861, 43862, 43863, 43864, 43865, 43866, 43867, 43868, 43869, 43870, 43871, 43872, 43873, 43874, 43875, 43876, 43877, 43878);
  script_xref(name:"SSA", value:"2008-089-01");

  script_name(english:"Slackware 10.2 / 11.0 / 12.0 / current : mozilla-firefox (SSA:2008-089-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New mozilla-firefox packages are available for Slackware 10.2, 11.0,
12.0, and -current to fix security issues."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3462ca90"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.380784
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb0c1b3a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"mozilla-firefox", pkgver:"2.0.0.13", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"11.0", pkgname:"mozilla-firefox", pkgver:"2.0.0.13", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"12.0", pkgname:"mozilla-firefox", pkgver:"2.0.0.13", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla-firefox", pkgver:"2.0.0.13", pkgarch:"i686", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
