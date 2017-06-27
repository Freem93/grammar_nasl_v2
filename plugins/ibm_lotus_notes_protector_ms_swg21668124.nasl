#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74121);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id(
    "CVE-2014-0884",
    "CVE-2014-0885",
    "CVE-2014-0886",
    "CVE-2014-0887"
  );
  script_bugtraq_id(66402, 66404, 66405, 66410);
  script_osvdb_id(104900, 104901, 104902, 104903);

  script_name(english:"IBM Lotus Protector for Mail Security Multiple Vulnerabilities");
  script_summary(english:"Checks version of IBM Lotus Protector package.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A version of IBM Lotus Protector for Mail Security is installed on the
remote host that is affected by multiple vulnerabilities :

  - An unspecified cross-site scripting vulnerability
    exists in the Admin Web UI.
    (CVE-2014-0884)

  - An unspecified cross-site request forgery vulnerability
    exists in the Admin Web UI. (CVE-2014-0885)

  - An unspecified arbitrary command execution
    vulnerability exists in the Admin Web UI.
    (CVE-2014-0886)

  - An unspecified arbitrary command execution
    vulnerability exists in the Admin Web UI that
    potentially allows an attacker to execute arbitrary
    commands with root privileges. (CVE-2014-0887)");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_multiple_security_vulnerabilities_in_admin_web_ui_for_ibm_lotus_protector_for_mail_security_cve_2014_0887_cve_2014_0886_cve_2014_0885_cve_2014_08841?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afbae2be");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21668124");
  script_set_attribute(attribute:"solution", value:"Install the latest system packages per the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_protector_for_mail_security");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^SLES1[01]") audit(AUDIT_OS_NOT, "SLES 10/11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;
# If 2.8.0, flag. 2.8.0 does not have the isslmi package, so we look
# at the core mailsec package. This package is upgraded to 3.0 in
# 2.8.1.
if (rpm_exists(release:"SLES10", rpm:"mailsec-2.8"))
{
  __rpm_report =
    'Version 2.8.0 is installed.' +
    '\nUpgrade to 2.8.1 and install the latest system packages.' +
    '\n';
  flag++;
}

# Check for updated system package in 2.8.1
if (rpm_check(release:"SLES11", reference:"isslmi-2.8.1-22905")) flag++;

if (flag)
{
  set_kb_item(name:"www/0/XSRF", value:TRUE);
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
