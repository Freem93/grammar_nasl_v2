#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41273);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/04/23 18:14:43 $");

  script_cve_id("CVE-2006-3835");

  script_name(english:"SuSE9 Security Update : Tomcat (YOU Patch Number 12343)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two old but not yet fixed security issues in tomcat5 were spotted and
are fixed by this update :

  - Apache Tomcat 5 before 5.5.17 allows remote attackers to
    list directories via a semicolon (;) preceding a
    filename with a mapped extension, as demonstrated by
    URLs ending with /;index.jsp and /;help.do.
    (CVE-2006-3835)

Cross-site scripting (XSS) vulnerability in certain applications using
Apache Tomcat allowed remote attackers to inject arbitrary web script
or HTML via crafted 'Accept-Language headers that do not conform to
RFC 2616'.

These issues were rated 'low' by the Apache Tomcat team."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3835.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12343.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SUSE9", reference:"apache-jakarta-tomcat-connectors-5.0.19-29.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"apache2-jakarta-tomcat-connectors-5.0.19-29.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"jakarta-tomcat-5.0.19-29.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"jakarta-tomcat-doc-5.0.19-29.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"jakarta-tomcat-examples-5.0.19-29.20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
