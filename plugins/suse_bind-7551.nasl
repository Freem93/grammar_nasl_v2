#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57160);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/17 10:53:20 $");

  script_cve_id("CVE-2011-1910");

  script_name(english:"SuSE 10 Security Update : bind (ZYPP Patch Number 7551)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides bind 9.6ESVR4P1 which fixes a denial of service
vulnerability that can be triggered by very large RRSIG RRsets in a
negative response and crash named. (CVE-2011-1910)

It further provides a fix for a defect which may cause queries for
.com names to fail with validation errors when DNSSEC records for the
.com zone are initially inserted into the root zone.

Please refer to https://www.isc.org/software/bind/new-features/9.6 for
more information on additional improvements and bug fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1910.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7551.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"bind-libs-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"bind-utils-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"bind-libs-32bit-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-chrootenv-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-devel-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-doc-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-libs-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"bind-utils-9.6ESVR4P1-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"bind-libs-32bit-9.6ESVR4P1-0.12.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
