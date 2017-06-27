#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29436);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/10/28 10:42:46 $");

  script_cve_id("CVE-2006-3467");

  script_name(english:"SuSE 10 Security Update : freetype2 (ZYPP Patch Number 1918)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update fixes crashes in the PCF handling of freetype2
which might be used to crash freetype2 using applications or even to
execute code in them.

This issue is tracked by the Mitre CVE ID CVE-2006-3467."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3467.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 1918.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:0, reference:"freetype2-2.1.10-18.8")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"freetype2-devel-2.1.10-18.8")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"freetype2-32bit-2.1.10-18.8")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"freetype2-devel-32bit-2.1.10-18.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"freetype2-2.1.10-18.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"freetype2-devel-2.1.10-18.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"freetype2-32bit-2.1.10-18.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"freetype2-devel-32bit-2.1.10-18.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
