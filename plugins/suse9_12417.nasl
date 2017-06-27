#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41300);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2007-6725", "CVE-2009-0196", "CVE-2009-0792");

  script_name(english:"SuSE9 Security Update : GhostScript (YOU Patch Number 12417)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted file could cause a heap-overflow in JBIG2 decoder
(CVE-2009-0196), an integer overflow in ICC library (CVE-2009-0792) or
crash the CCITTFax decoder. (CVE-2007-6725)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6725.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0792.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12417.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SUSE9", reference:"ghostscript-fonts-other-7.07.1rc1-195.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-fonts-rus-7.07.1rc1-195.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-fonts-std-7.07.1rc1-195.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-library-7.07.1rc1-195.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-serv-7.07.1rc1-195.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-x11-7.07.1rc1-195.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"libgimpprint-4.2.6-46.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"libgimpprint-devel-4.2.6-46.17")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
