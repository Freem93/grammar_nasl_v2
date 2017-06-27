#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29603);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2007-4568", "CVE-2007-4730", "CVE-2007-4990");

  script_name(english:"SuSE 10 Security Update : X.org X11 (ZYPP Patch Number 4485)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues :

X Font Server build_range() Integer Overflow Vulnerability [IDEF2708]
(CVE-2007-4989), X Font Server swap_char2b() Heap Overflow
Vulnerability [IDEF2709] (CVE-2007-4990), Composite extension buffer
overflow. (CVE-2007-4730)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4989.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4990.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4485.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/03");
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
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-Xnest-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-Xvfb-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-Xvnc-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-devel-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-fonts-100dpi-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-fonts-75dpi-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-fonts-cyrillic-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-fonts-scalable-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-fonts-syriac-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-libs-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-man-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-server-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-server-glx-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-Xnest-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-Xvfb-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-Xvnc-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-devel-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-doc-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-fonts-100dpi-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-fonts-75dpi-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-fonts-cyrillic-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-fonts-scalable-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-fonts-syriac-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-libs-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-man-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-sdk-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-server-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-server-glx-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.52")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.52")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
