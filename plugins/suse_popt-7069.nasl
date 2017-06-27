#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49917);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/05/17 11:20:15 $");

  script_cve_id("CVE-2010-2059");

  script_name(english:"SuSE 10 Security Update : popt (ZYPP Patch Number 7069)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a security problem where RPM misses to clear the
SUID/SGID bit of old files during package updates. (CVE-2010-2059)

Also the following bugs were fixed :

  - do not use glibc for passwd/group lookups when --root is
    used [bnc#536256]

  - disable cpio md5 checking for repackaged rpms
    [bnc#572280]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2059.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7069.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"popt-1.7-271.36.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"popt-devel-1.7-271.36.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"rpm-4.4.2-43.36.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"rpm-devel-4.4.2-43.36.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"rpm-python-4.4.2-43.36.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"popt-32bit-1.7-271.36.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"popt-devel-32bit-1.7-271.36.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"popt-1.7-271.36.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"popt-devel-1.7-271.36.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"rpm-4.4.2-43.36.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"rpm-devel-4.4.2-43.36.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"rpm-python-4.4.2-43.36.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"popt-32bit-1.7-271.36.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"popt-devel-32bit-1.7-271.36.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
