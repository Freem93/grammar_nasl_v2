#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46013);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/07/20 01:58:54 $");

  script_cve_id("CVE-2010-0408", "CVE-2010-0434");

  script_name(english:"SuSE 10 Security Update : Apache 2 (ZYPP Patch Number 6984)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following bugs have been fixed :

When using a multi-threaded MPM apache could leak memory of requests
handled by a different thread when processing subrequests
(CVE-2010-0434). Specially crafted requests could crash mod_proxy_ajp.
(CVE-2010-0408)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0408.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0434.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6984.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:2, reference:"apache2-2.2.3-16.25.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"apache2-devel-2.2.3-16.25.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"apache2-doc-2.2.3-16.25.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"apache2-example-pages-2.2.3-16.25.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"apache2-prefork-2.2.3-16.25.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"apache2-worker-2.2.3-16.25.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
