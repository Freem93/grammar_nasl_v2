#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-178-03. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21767);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:36:13 $");

  script_cve_id("CVE-2006-2916");
  script_osvdb_id(26506);
  script_xref(name:"SSA", value:"2006-178-03");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / current : arts (SSA:2006-178-03)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New aRts packages are available for Slackware 10.0, 10.1, 10.2, and
-current to fix a possible security issue with artswrapper. The
artswrapper program and the artsd daemon can be used to gain root
privileges if artswrapper is setuid root and the system is running a
2.6.x kernel. Note that artswrapper is not setuid root on Slackware by
default. Some people have recommended setting it that way online
though, so it's at least worth warning about. It's far safer to just
add users to the audio group. The official KDE security advisory may
be found here:
http://www.kde.org/info/security/advisory-20060614-2.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20060614-2.txt"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.468256
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?086b2a3e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected arts package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:arts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.0", pkgname:"arts", pkgver:"1.2.3", pkgarch:"i486", pkgnum:"2_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"arts", pkgver:"1.3.2", pkgarch:"i486", pkgnum:"2_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"arts", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"2_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"arts", pkgver:"1.5.3", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
