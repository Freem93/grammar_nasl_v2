#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42794);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/02/08 11:51:47 $");

  script_cve_id("CVE-2009-2700");

  script_name(english:"SuSE 10 Security Update : Qt3 (ZYPP Patch Number 6644)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the handling of the subjectAltName field in SSL
certificates. (CVE-2009-2700)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2700.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6644.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, reference:"dbus-1-qt-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"qt-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"qt-qt3support-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"qt-sql-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"qt-x11-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"dbus-1-qt-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"qt-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"qt-qt3support-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"qt-sql-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"qt-x11-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"dbus-1-qt-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"qt-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"qt-qt3support-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"qt-sql-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"qt-x11-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"dbus-1-qt-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"qt-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"qt-qt3support-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"qt-sql-32bit-4.3.4-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"qt-x11-32bit-4.3.4-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");