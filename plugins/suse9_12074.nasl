#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41196);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/04/23 18:14:42 $");

  script_cve_id("CVE-2008-0411");

  script_name(english:"SuSE9 Security Update : Ghostscript (YOU Patch Number 12074)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack-based buffer overflow was fixed in the ghostscript
interpreter, which potentially could be used to execute code or at
least crash ghostscript. (CVE-2008-0411)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0411.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12074.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SUSE9", reference:"ghostscript-fonts-other-7.07.1rc1-195.11")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-fonts-rus-7.07.1rc1-195.11")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-fonts-std-7.07.1rc1-195.11")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-library-7.07.1rc1-195.11")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-serv-7.07.1rc1-195.11")) flag++;
if (rpm_check(release:"SUSE9", reference:"ghostscript-x11-7.07.1rc1-195.11")) flag++;
if (rpm_check(release:"SUSE9", reference:"libgimpprint-4.2.6-46.10")) flag++;
if (rpm_check(release:"SUSE9", reference:"libgimpprint-devel-4.2.6-46.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
