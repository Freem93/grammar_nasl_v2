#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52525);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2010-3718", "CVE-2011-0013");

  script_name(english:"SuSE 10 Security Update : Tomcat (ZYPP Patch Number 7337)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This tomcat6 update fixes :

  - CVE-2010-3718: CVSS v2 Base Score: 4.0
    (AV:N/AC:H/Au:N/C:P/I:P/A:N): Design Error
    (CWE-DesignError)

  - CVE-2011-0013: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:P/A:N): XSS (CWE-79)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0013.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7337.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"tomcat5-5.5.27-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"tomcat5-admin-webapps-5.5.27-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"tomcat5-webapps-5.5.27-0.12.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
