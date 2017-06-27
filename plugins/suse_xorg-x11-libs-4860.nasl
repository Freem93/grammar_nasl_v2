#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(30041);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");

  script_name(english:"SuSE 10 Security Update : X11 libs and server (ZYPP Patch Number 4860)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various Xserver security issues. File existence
disclosure vulnerability. (CVE-2007-5958)

XInput Extension Memory Corruption Vulnerability [IDEF2888
CVE-2007-6427].

TOG-CUP Extension Memory Corruption Vulnerability [IDEF2901
CVE-2007-6428].

EVI Extension Integer Overflow Vulnerability [IDEF2902 CVE-2007-6429].

MIT-SHM Extension Integer Overflow Vulnerability [IDEF2904
CVE-2007-6429]. 

XFree86-MISC Extension Invalid Array Index Vulnerability [IDEF2903
CVE-2007-5760]. 

PCF font parser vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5760.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5958.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6429.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4860.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-libs-6.9.0-50.54.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"xorg-x11-server-6.9.0-50.54.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.54.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-libs-6.9.0-50.54.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xorg-x11-server-6.9.0-50.54.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.54.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
