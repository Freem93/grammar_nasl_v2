#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53401);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/15 13:47:38 $");

  script_cve_id("CVE-2011-0465");
  script_xref(name:"IAVA", value:"2017-A-0098");

  script_name(english:"SuSE9 Security Update : XFree86 (YOU Patch Number 12700)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following bug has been fixed :

  - Remote attackers could execute arbitrary commands as
    root by assigning specially crafted hostnames to X11
    clients via XDMCP. (CVE-2011-0465)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0465.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12700.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SUSE9", reference:"XFree86-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-Mesa-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-Mesa-devel-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-Xnest-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-Xprt-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-Xvfb-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-Xvnc-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-devel-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-doc-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-driver-options-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-fonts-100dpi-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-fonts-75dpi-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-fonts-cyrillic-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-fonts-scalable-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-fonts-syriac-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-libs-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-man-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-server-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"XFree86-server-glx-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", reference:"km_drm-4.3.99.902-43.105")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"XFree86-Mesa-32bit-9-201104080857")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"XFree86-Mesa-devel-32bit-9-201104080857")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"XFree86-devel-32bit-9-201104080857")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"XFree86-libs-32bit-9-201104080857")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
