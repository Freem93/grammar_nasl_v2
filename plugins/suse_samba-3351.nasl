#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29576);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2012/05/17 11:20:15 $");

  script_cve_id("CVE-2007-2446", "CVE-2007-2447");

  script_name(english:"SuSE 10 Security Update : Samba (ZYPP Patch Number 3351)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted MS-RPC packets could overwrite heap memory and
therfore could potentially be exploited to execute code.
(CVE-2007-2446)

Authenticated users could leverage specially crafted MS-RPC packets to
pass arguments unfiltered to /bin/sh. (CVE-2007-2447)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2447.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3351.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:0, reference:"samba-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"samba-client-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"samba-winbind-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"samba-32bit-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"samba-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"samba-client-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"samba-winbind-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"samba-32bit-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.0.22-13.30")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.22-13.30")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
