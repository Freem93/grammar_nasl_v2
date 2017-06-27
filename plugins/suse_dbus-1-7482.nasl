#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57177);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/17 11:05:45 $");

  script_cve_id("CVE-2008-3834", "CVE-2009-1189", "CVE-2010-4352");

  script_name(english:"SuSE 10 Security Update : dbus (ZYPP Patch Number 7482)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Local users could crash the D-Bus daemon by sending a specially
crafted message (CVE-2010-4352). This update also properly fixes
CVE-2008-3834 / CVE-2009-1189."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1189.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4352.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7482.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/26");
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
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-devel-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-glib-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-gtk-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-mono-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-python-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-qt3-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-qt3-devel-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dbus-1-x11-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"dbus-1-32bit-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"dbus-1-glib-32bit-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"dbus-1-qt3-32bit-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-devel-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-glib-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-gtk-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-java-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-mono-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-python-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-qt3-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-qt3-devel-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dbus-1-x11-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"dbus-1-32bit-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"dbus-1-glib-32bit-0.60-33.29.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"dbus-1-qt3-32bit-0.60-33.29.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
