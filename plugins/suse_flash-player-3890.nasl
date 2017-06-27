#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29434);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2007-2022", "CVE-2007-3456", "CVE-2007-3457");

  script_name(english:"SuSE 10 Security Update : flash-player (ZYPP Patch Number 3890)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Adobe Flash Player was updated to version 7.0.70.0 for Novell
Linux Desktop 9 and to version 9.0.48.0 on SUSE Linux Enterprise
Desktop 10 to fix several security problems :

  - An input validation error has been identified in Flash
    Player 9.0.45.0 and earlier versions that could lead to
    the potential execution of arbitrary code. This
    vulnerability could be accessed through content
    delivered from a remote location via the user's web
    browser, email client, or other applications that
    include or reference the Flash Player. (CVE-2007-3456)

  - An issue with insufficient validation of the HTTP
    Referer has been identified in Flash Player 8.0.34.0 and
    earlier. This issue does not affect Flash Player 9. This
    issue could potentially aid an attacker in executing a
    cross-site request forgery attack. (CVE-2007-3457)

  - The Linux and Solaris updates for Flash Player 7
    (7.0.70.0) address the issues with Flash Player and the
    Opera and Konqueror browsers described in Security
    Advisory APSA07-03. These issues do not impact Flash
    Player 9 on Linux or Solaris. (CVE-2007-2022)

The affected webbrowsers Opera and konqueror have already been fixed
independendly."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3457.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3890.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 200, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"flash-player-9.0.48.0-1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
