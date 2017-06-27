#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41166);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/04/23 18:14:42 $");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

  script_name(english:"SuSE9 Security Update : Cups (YOU Patch Number 11965)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities have been found in the xpdf code used by
cups which could be exploited, potentially remotely, by tricking the
user to print a specially crafted PDF file.

The vulnerabilities are in the source code file Stream.cc and may
allow execution of arbitrary code with the privileges of the user
viewing the PDF. Specifically, these are an array indexing error
leading to memory corruption (CVE-2007-4352), a possible integer
overflow causing to a buffer overflow (CVE-2007-5392) and a boundary
check error that can also cause a buffer overflow. (CVE-2007-5393)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5392.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5393.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 11965.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
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
if (rpm_check(release:"SUSE9", reference:"cups-1.1.20-108.44")) flag++;
if (rpm_check(release:"SUSE9", reference:"cups-client-1.1.20-108.44")) flag++;
if (rpm_check(release:"SUSE9", reference:"cups-devel-1.1.20-108.44")) flag++;
if (rpm_check(release:"SUSE9", reference:"cups-libs-1.1.20-108.44")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"cups-libs-32bit-9-200711080439")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
