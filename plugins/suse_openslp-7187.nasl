#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50842);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/05/17 11:20:15 $");

  script_cve_id("CVE-2010-3609");

  script_name(english:"SuSE 10 Security Update : openslp (ZYPP Patch Number 7187)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openslp daemon could run into an endless loop when receiving
specially crafted packets (CVE-2010-3609). This has been fixed.

Additionally the following non-security bugs were fixed :

  - This openSLP update extends the net.slp.isDABackup
    mechanism introduced with the previous update by a new
    configuration option 'DABackupLocalReg'.

  - This option tells the openslp server to also backup
    local registrations. (bnc#597215)

  - In addition, standard compliance was fixed by stripping
    leading and trailing white spaces when doing string
    comparisons of scopes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3609.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7187.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/30");
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
if (rpm_check(release:"SLED10", sp:3, reference:"openslp-1.2.0-22.31.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"openslp-devel-1.2.0-22.31.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"openslp-32bit-1.2.0-22.31.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"openslp-1.2.0-22.31.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"openslp-devel-1.2.0-22.31.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"openslp-server-1.2.0-22.31.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"openslp-32bit-1.2.0-22.31.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
