#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65026);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/05 11:50:59 $");

  script_cve_id("CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");

  script_name(english:"SuSE 10 Security Update : pidgin (ZYPP Patch Number 8475)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pidgin was updated to fix 4 security issues :

  - Fixed a crash when receiving UPnP responses with
    abnormally long values. (CVE-2013-0274, bnc#804742)

  - Fixed a crash in Sametime protocol when a malicious
    server sends us an abnormally long user ID.
    (CVE-2013-0273, bnc#804742)

  - Fixed a bug where the MXit server or a man-in-the-middle
    could potentially send specially crafted data that could
    overflow a buffer and lead to a crash or remote code
    execution. (CVE-2013-0272, bnc#804742)

  - Fixed a bug where a remote MXit user could possibly
    specify a local file path to be written to.
    (CVE-2013-0271, bnc#804742)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0274.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8475.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"finch-2.6.6-0.20.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libpurple-2.6.6-0.20.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"pidgin-2.6.6-0.20.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
