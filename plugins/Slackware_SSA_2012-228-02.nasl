#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2012-228-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61553);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/03/21 10:44:31 $");

  script_cve_id("CVE-2012-3479");
  script_bugtraq_id(54969);
  script_xref(name:"SSA", value:"2012-228-02");

  script_name(english:"Slackware 13.1 / 13.37 / current : emacs (SSA:2012-228-02)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New emacs packages are available for Slackware 13.1, 13.37, and
-current to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2012&m=slackware-security.420006
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27d1aa42"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected emacs package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.1", pkgname:"emacs", pkgver:"23.2", pkgarch:"i486", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"emacs", pkgver:"23.2", pkgarch:"x86_64", pkgnum:"2_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"emacs", pkgver:"23.3", pkgarch:"i486", pkgnum:"2_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"emacs", pkgver:"23.3", pkgarch:"x86_64", pkgnum:"2_slack13.37")) flag++;

if (slackware_check(osver:"current", pkgname:"emacs", pkgver:"24.1", pkgarch:"i486", pkgnum:"6")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"emacs", pkgver:"24.1", pkgarch:"x86_64", pkgnum:"6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
