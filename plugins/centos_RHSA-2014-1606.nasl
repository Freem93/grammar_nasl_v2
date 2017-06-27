#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1606 and 
# CentOS Errata and Security Advisory 2014:1606 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79185);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2012-1571", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943", "CVE-2014-2270", "CVE-2014-3479", "CVE-2014-3480");
  script_bugtraq_id(52225, 65596, 66002, 67759, 67765, 68238, 68241);
  script_osvdb_id(79681, 107559, 107560, 108465, 108466);
  script_xref(name:"RHSA", value:"2014:1606");

  script_name(english:"CentOS 6 : file (CESA-2014:1606)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated file packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The 'file' command is used to identify a particular file according to
the type of data contained in the file. The command can identify
various file types, including ELF binaries, system libraries, RPM
packages, and different graphics formats.

Multiple denial of service flaws were found in the way file parsed
certain Composite Document Format (CDF) files. A remote attacker could
use either of these flaws to crash file, or an application using file,
via a specially crafted CDF file. (CVE-2014-0237, CVE-2014-0238,
CVE-2014-3479, CVE-2014-3480, CVE-2012-1571)

Two denial of service flaws were found in the way file handled
indirect and search rules. A remote attacker could use either of these
flaws to cause file, or an application using file, to crash or consume
an excessive amount of CPU. (CVE-2014-1943, CVE-2014-2270)

This update also fixes the following bugs :

* Previously, the output of the 'file' command contained redundant
white spaces. With this update, the new STRING_TRIM flag has been
introduced to remove the unnecessary white spaces. (BZ#664513)

* Due to a bug, the 'file' command could incorrectly identify an XML
document as a LaTex document. The underlying source code has been
modified to fix this bug and the command now works as expected.
(BZ#849621)

* Previously, the 'file' command could not recognize .JPG files and
incorrectly labeled them as 'Minix filesystem'. This bug has been
fixed and the command now properly detects .JPG files. (BZ#873997)

* Under certain circumstances, the 'file' command incorrectly detected
NETpbm files as 'x86 boot sector'. This update applies a patch to fix
this bug and the command now detects NETpbm files as expected.
(BZ#884396)

* Previously, the 'file' command incorrectly identified ASCII text
files as a .PIC image file. With this update, a patch has been
provided to address this bug and the command now correctly recognizes
ASCII text files. (BZ#980941)

* On 32-bit PowerPC systems, the 'from' field was missing from the
output of the 'file' command. The underlying source code has been
modified to fix this bug and 'file' output now contains the 'from'
field as expected. (BZ#1037279)

* The 'file' command incorrectly detected text files as 'RRDTool DB
version ool - Round Robin Database Tool'. This update applies a patch
to fix this bug and the command now correctly detects text files.
(BZ#1064463)

* Previously, the 'file' command supported only version 1 and 2 of the
QCOW format. As a consequence, file was unable to detect a 'qcow2
compat=1.1' file created on Red Hat Enterprise Linux 7. With this
update, support for QCOW version 3 has been added so that the command
now detects such files as expected. (BZ#1067771)

All file users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2014-October/001176.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?154ce34c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"file-5.04-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"file-devel-5.04-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"file-libs-5.04-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"file-static-5.04-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-magic-5.04-21.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
