#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56600);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/13 15:30:42 $");

  script_cve_id("CVE-2011-3192");

  script_name(english:"SuSE 10 Security Update : Apache (ZYPP Patch Number 7721)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a remote denial of service bug (memory exhaustion)
in the Apache 2 HTTP server, that could be triggered by remote
attackers using multiple overlapping Request Ranges. (CVE-2011-3192)

It also fixes some non-security bugs :

  - take LimitRequestFieldsize config option into account
    when parsing headers from backend. Thereby avoid that
    the receiving buffers are too small. bnc#690734.

  - add / when on a directory to feed correctly linked
    listings. bnc#661597: * a2enmod shalt not disable a
    module in query mode. bnc#663359

  - New option SSLRenegBufferSize fixes '413 Request Entity
    Too Large occur' problem.

  - fixes graceful restart hangs, bnc#555098."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3192.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7721.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-2.2.3-16.32.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-devel-2.2.3-16.32.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-doc-2.2.3-16.32.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-example-pages-2.2.3-16.32.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-prefork-2.2.3-16.32.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-worker-2.2.3-16.32.35.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
