#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49255);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/13 15:30:41 $");

  script_cve_id("CVE-2010-1157", "CVE-2010-2227");

  script_name(english:"SuSE9 Security Update : Tomcat (YOU Patch Number 12625)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of tomcat fixes a denial of service vulnerability and two
information disclosure flaws which could potentially be exploited by
remote attackers to crash tomcat or to obtain sensitive information.
(CVE-2010-2227, CVE-2010-1157)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2227.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12625.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"apache-jakarta-tomcat-connectors-5.0.19-29.27")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-jakarta-tomcat-connectors-5.0.19-29.27")) flag++;
if (rpm_check(release:"SUSE9", reference:"jakarta-tomcat-5.0.19-29.27")) flag++;
if (rpm_check(release:"SUSE9", reference:"jakarta-tomcat-doc-5.0.19-29.27")) flag++;
if (rpm_check(release:"SUSE9", reference:"jakarta-tomcat-examples-5.0.19-29.27")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
