#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49921);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/05/17 11:20:15 $");

  script_cve_id("CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");

  script_name(english:"SuSE 10 Security Update : postgresql (ZYPP Patch Number 7053)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of postgresql fixes several minor security 
vulnerabilities :

  - Postgresql does not properly check privileges during
    certain RESET ALL operations, which allows remote
    authenticated users to remove arbitrary parameter
    settings. (CVE-2010-1975)

  - The PL/Tcl implementation in postgresql loads Tcl code
    from the pltcl_modules table regardless of the table's
    ownership and permissions, which allows remote
    authenticated users with database creation privileges to
    execute arbitrary Tcl code. (CVE-2010-1170)

  - Postgresql does not properly restrict PL/perl
    procedures, which allows remote authenticated users with
    database creation privileges to execute arbitrary Perl
    code via a crafted script. (CVE-2010-1169)

  - An integer overflow in postgresql allows remote
    authenticated users to crash the daemon with a SELECT
    statement. (CVE-2010-0733)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1975.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7053.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"postgresql-devel-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"postgresql-libs-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"postgresql-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"postgresql-contrib-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"postgresql-devel-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"postgresql-docs-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"postgresql-libs-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"postgresql-pl-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"postgresql-server-8.1.21-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.21-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
