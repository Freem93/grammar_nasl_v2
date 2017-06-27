#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54829);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/10/03 00:00:33 $");

  script_cve_id("CVE-2011-1098", "CVE-2011-1155");

  script_name(english:"SuSE 10 Security Update : logrotate (ZYPP Patch Number 7534)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for logrotate provides the following fixes :

  - Race condition in the createOutputFile function in
    logrotate allows local users to read log data by opening
    a file before the intended permissions are in place
    (CVE-2011-1098). (bnc#677336)

  - The writeState function in logrotate might allow
    context-dependent attackers to cause a denial of service
    (rotation outage) via a (1) \n (newline) or (2) \
    (backslash) character in a log filename, as demonstrated
    by a filename that is automatically constructed on the
    basis of a hostname or virtual machine name
    (CVE-2011-1155). (bnc#679662)

  - In addition, the missingok option has been improved"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1155.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7534.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"logrotate-3.7.3-13.13.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
