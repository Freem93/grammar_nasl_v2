#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46170);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902");

  script_name(english:"SuSE 10 Security Update : tomcat5 (ZYPP Patch Number 7003)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of Apache Tomcat 5 fixes the following security issues :

A directory traversal vulnerability allows remote attackers to create
or overwrite arbitrary files and directories with a specially crafted
WAR file (CVE-2009-2693 / CVE-2009-2902). When autoDeploy is enabled,
the automatic deployment process deploys appBase files that remain
from a failed undeploy, which might allow remote attackers to bypass
intended authentication requirements via HTTP requests.
(CVE-2009-2901)

Note that this is a re-release of the security update to correct a
regression. The previous patch caused tomcat to delete files it
spuriously associated with a failed undeploy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2693.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2901.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2902.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:2, reference:"tomcat5-5.0.30-27.45")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"tomcat5-admin-webapps-5.0.30-27.45")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"tomcat5-webapps-5.0.30-27.45")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
