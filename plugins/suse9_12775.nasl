#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55440);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/04/23 18:21:33 $");

  script_cve_id("CVE-2011-0536", "CVE-2011-1071", "CVE-2011-1095");

  script_name(english:"SuSE9 Security Update : glibc (YOU Patch Number 12775)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update contains the following fixes :

  - Specially crafted input to the fnmatch function could
    cause an integer overflow. (CVE-2011-1071)

  - The output of the 'locale' command was not properly
    quoted. (CVE-2011-1095)

  - Don't search the current directory if $ORIGIN is in
    RPATH of libraries called by setuid binaries.
    (CVE-2011-0536)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1095.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12775.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"glibc-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-devel-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-html-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-i18ndata-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-info-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-locale-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-profile-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"nscd-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", reference:"timezone-2.3.3-98.121")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glibc-32bit-9-201106161950")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glibc-devel-32bit-9-201106161606")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glibc-locale-32bit-9-201106161606")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
