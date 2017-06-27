#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58791);
  script_version ("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/05/17 11:05:46 $");

  script_cve_id("CVE-2009-3743", "CVE-2010-4054");

  script_name(english:"SuSE 10 Security Update : ghostscript (ZYPP Patch Number 8063)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ghostscript fixes two security issues :

  - Off-by-one error in the TrueType bytecode interpreter in
    Ghostscript in SUSE Linux Enterprise 10 and 11 products
    allows remote attackers to cause a denial of service
    (heap memory corruption) via a malformed TrueType font
    in a document. (CVE-2009-3743)

  - The gs_type2_interpret function in Ghostscript allows
    remote attackers to cause a denial of service (incorrect
    pointer dereference and application crash) via crafted
    font data in a compressed data stream. (CVE-2010-4054)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4054.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8063.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"ghostscript-fonts-other-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"ghostscript-fonts-std-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"ghostscript-library-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"ghostscript-x11-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libgimpprint-4.2.7-62.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ghostscript-fonts-other-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ghostscript-fonts-rus-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ghostscript-fonts-std-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ghostscript-library-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ghostscript-omni-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ghostscript-x11-8.15.4-16.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libgimpprint-4.2.7-62.26.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libgimpprint-devel-4.2.7-62.26.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
