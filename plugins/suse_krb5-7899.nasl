#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57431);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/15 16:41:30 $");

  script_cve_id("CVE-2011-1526", "CVE-2011-4862");

  script_name(english:"SuSE 10 Security Update : Kerberos 5 (ZYPP Patch Number 7899)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of krb5 fixes two security issues.

  - A remote code execution in the kerberized telnet daemon
    was fixed. (This only affects the ktelnetd from the
    krb5-appl RPM, not the regular telnetd supplied by
    SUSE.). (CVE-2011-4862)

  - / MITKRB5-SA-2011-005: Fixed krb5 ftpd unauthorized file
    access problems. (CVE-2011-1526)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4862.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7899.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"krb5-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"krb5-client-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"krb5-devel-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"krb5-32bit-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"krb5-devel-32bit-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"krb5-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"krb5-apps-clients-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"krb5-apps-servers-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"krb5-client-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"krb5-devel-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"krb5-server-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"krb5-32bit-1.4.3-19.49.49.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"krb5-devel-32bit-1.4.3-19.49.49.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
