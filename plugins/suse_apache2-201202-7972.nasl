#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58166);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2007-6750", "CVE-2012-0031", "CVE-2012-0053");

  script_name(english:"SuSE 10 Security Update : Apache2 (ZYPP Patch Number 7972)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of apache fixes regressions and several security 
problems :

  - Fixed a scoreboard corruption (shared mem segment) by
    child causes crash of privileged parent (invalid free())
    during shutdown. (bnc#741243, CVE-2012-0031)

  - Fixed an issue in error responses that could expose
    'httpOnly' cookies when no custom ErrorDocument is
    specified for status code 400'.
    (bnc#743743,CVE-2012-0053)

  - the SSL configuration template suggested weak ciphers.
    (bnc#736706)

  - The 'mod_reqtimeout' module was backported from Apache
    2.2.21 to help mitigate the 'Slowloris' Denial of
    Service attack. (bnc#738855,CVE-2007-6750)

    You need to enable the 'mod_reqtimeout' module in your
    existing apache configuration to make it effective, e.g.
    in the APACHE_MODULES line in /etc/sysconfig/apache2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6750.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0053.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7972.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-2.2.3-16.44.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-devel-2.2.3-16.44.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-doc-2.2.3-16.44.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-example-pages-2.2.3-16.44.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-prefork-2.2.3-16.44.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-worker-2.2.3-16.44.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");