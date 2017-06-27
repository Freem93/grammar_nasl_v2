#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2008-241-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34061);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/30 13:52:22 $");

  script_cve_id("CVE-2008-3699");
  script_bugtraq_id(30662);
  script_osvdb_id(47455);
  script_xref(name:"SSA", value:"2008-241-01");

  script_name(english:"Slackware 11.0 / 12.0 / 12.1 / current : amarok (SSA:2008-241-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Amarok packages are available for Slackware 11.0, 12.0, 12.1, and
-current to fix security issues. In addition, new supporting libgpod
packages are available for Slackware 11.0 and 12.0, since a newer
version of libgpod than shipped with these releases is required to run
Amarok version 1.4.10. The Magnatune music library plugin made
insecure use of the /tmp directory, allowing malicious local users to
overwrite files owned by the user running Amarok through symlink
attacks."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.455790
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2aaa50fe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected amarok and / or libgpod packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:amarok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libgpod");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/30");
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
if (slackware_check(osver:"11.0", pkgname:"amarok", pkgver:"1.4.10", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;
if (slackware_check(osver:"11.0", pkgname:"libgpod", pkgver:"0.6.0", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"amarok", pkgver:"1.4.10", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"libgpod", pkgver:"0.6.0", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"amarok", pkgver:"1.4.10", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;

if (slackware_check(osver:"current", pkgname:"amarok", pkgver:"1.4.10", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:slackware_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
