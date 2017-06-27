#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78843);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/04 14:19:38 $");

  script_cve_id("CVE-2012-1571", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943", "CVE-2014-2270", "CVE-2014-3479", "CVE-2014-3480");

  script_name(english:"Scientific Linux Security Update : file on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple denial of service flaws were found in the way file parsed
certain Composite Document Format (CDF) files. A remote attacker could
use either of these flaws to crash file, or an application using file,
via a specially crafted CDF file. (CVE-2014-0237, CVE-2014-0238,
CVE-2014-3479, CVE-2014-3480, CVE-2012-1571)

Two denial of service flaws were found in the way file handled
indirect and search rules. A remote attacker could use either of these
flaws to cause file, or an application using file, to crash or consume
an excessive amount of CPU. (CVE-2014-1943, CVE-2014-2270)

This update also fixes the following bugs :

  - Previously, the output of the 'file' command contained
    redundant white spaces. With this update, the new
    STRING_TRIM flag has been introduced to remove the
    unnecessary white spaces.

  - Due to a bug, the 'file' command could incorrectly
    identify an XML document as a LaTex document. The
    underlying source code has been modified to fix this bug
    and the command now works as expected.

  - Previously, the 'file' command could not recognize .JPG
    files and incorrectly labeled them as 'Minix
    filesystem'. This bug has been fixed and the command now
    properly detects .JPG files.

  - Under certain circumstances, the 'file' command
    incorrectly detected NETpbm files as 'x86 boot sector'.
    This update applies a patch to fix this bug and the
    command now detects NETpbm files as expected.

  - Previously, the 'file' command incorrectly identified
    ASCII text files as a .PIC image file. With this update,
    a patch has been provided to address this bug and the
    command now correctly recognizes ASCII text files.

  - On 32-bit PowerPC systems, the 'from' field was missing
    from the output of the 'file' command. The underlying
    source code has been modified to fix this bug and 'file'
    output now contains the 'from' field as expected.

  - The 'file' command incorrectly detected text files as
    'RRDTool DB version ool - Round Robin Database Tool'.
    This update applies a patch to fix this bug and the
    command now correctly detects text files.

  - Previously, the 'file' command supported only version 1
    and 2 of the QCOW format. As a consequence, file was
    unable to detect a 'qcow2 compat=1.1' file created on
    Scientific Linux 7. With this update, support for QCOW
    version 3 has been added so that the command now detects
    such files as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=1742
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6a15480"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"file-5.04-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-debuginfo-5.04-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-devel-5.04-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-libs-5.04-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-static-5.04-21.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-magic-5.04-21.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
