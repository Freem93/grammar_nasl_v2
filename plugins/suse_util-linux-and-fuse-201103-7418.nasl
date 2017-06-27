#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57257);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/17 11:27:19 $");

  script_cve_id("CVE-2010-3879", "CVE-2011-0541", "CVE-2011-0543");

  script_name(english:"SuSE 10 Security Update : fuse (ZYPP Patch Number 7418)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issues were fixed in fuse :

  - FUSE allowed local users to create mtab entries with
    arbitrary pathnames, and consequently unmount any
    filesystem, via a symlink attack on the parent directory
    of the mountpoint of a FUSE filesystem. (CVE-2010-3879)

  - Avoid mounting a directory including evaluation of
    symlinks, which might have allowed local attackers to
    mount filesystems anywhere in the system.
    (CVE-2011-0541)

  - Avoid symlink attacks on the mount point written in the
    mtab file. (CVE-2011-0543)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0543.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7418.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
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
if (rpm_check(release:"SLED10", sp:4, reference:"fuse-2.7.2-15.10.11.10")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"fuse-devel-2.7.2-15.10.11.10")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libfuse2-2.7.2-15.10.11.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
