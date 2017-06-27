#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(30182);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-5925", "CVE-2007-5969", "CVE-2007-6303", "CVE-2007-6304");

  script_name(english:"SuSE 10 Security Update : MySQL (ZYPP Patch Number 4879)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several security vulnerabilities (note: not all
versions are affected by every bug) :

  - CVE-2007-2583

  - CVE-2007-2691

  - CVE-2007-2692

  - CVE-2007-5925

  - CVE-2007-5969

  - CVE-2007-6303

  - CVE-2007-6304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5925.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5969.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6303.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6304.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4879.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_cwe_id(20, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/05");
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
if (rpm_check(release:"SLED10", sp:1, reference:"mysql-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"mysql-client-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"mysql-devel-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"mysql-shared-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"mysql-shared-32bit-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mysql-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mysql-Max-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mysql-client-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mysql-devel-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mysql-shared-5.0.26-12.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"mysql-shared-32bit-5.0.26-12.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");