#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41193);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:21:21 $");

  script_cve_id("CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");

  script_name(english:"SuSE9 Security Update : postgresql (YOU Patch Number 12065)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version update to 8.1.11 fixes among other things, several
security issues :

  - Index Functions Privilege Escalation: CVE-2007-6600

  - Regular Expression Denial-of-Service: CVE-2007-4772,
    CVE-2007-6067, CVE-2007-4769

  - DBLink Privilege Escalation: CVE-2007-6601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4769.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6601.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12065.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/01");
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
if (rpm_check(release:"SUSE9", reference:"postgresql-7.4.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"postgresql-contrib-7.4.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"postgresql-devel-7.4.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"postgresql-docs-7.4.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"postgresql-libs-7.4.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"postgresql-pl-7.4.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"postgresql-server-7.4.19-0.1")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"postgresql-libs-32bit-9-200801312100")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
