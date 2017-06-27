#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41229);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:21 $");

  script_cve_id("CVE-2008-1679", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");

  script_name(english:"SuSE9 Security Update : Python (YOU Patch Number 12215)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of python fixes several security vulnerabilities.
(CVE-2008-1679 / CVE-2008-1887, CVE-2008-3143, CVE-2008-3142,
CVE-2008-3144, CVE-2008-2315, CVE-2008-2316)

Note: for SLE10 a non-security bug in mmap was fixed too."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1679.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1887.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2315.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2316.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3144.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12215.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/01");
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
if (rpm_check(release:"SUSE9", reference:"python-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-curses-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-demo-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-devel-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-doc-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-doc-pdf-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-gdbm-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-idle-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-mpz-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-tk-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-xml-2.3.3-88.24")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"python-32bit-9-200808010009")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
