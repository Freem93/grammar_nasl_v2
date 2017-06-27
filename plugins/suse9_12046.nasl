#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41186);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/04/23 18:14:42 $");

  script_cve_id("CVE-2007-4965");

  script_name(english:"SuSE9 Security Update : Python (YOU Patch Number 12046)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted images could trigger an integer overflow in the
imageop module. (CVE-2007-4965)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4965.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12046.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/14");
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
if (rpm_check(release:"SUSE9", reference:"python-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-curses-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-demo-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-devel-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-doc-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-doc-pdf-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-gdbm-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-idle-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-mpz-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-tk-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-xml-2.3.3-88.20")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"python-32bit-9-200801101709")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
