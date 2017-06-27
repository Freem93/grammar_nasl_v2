#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-190.
#

include("compat.inc");

if (description)
{
  script_id(73126);
  script_version("$Revision $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id("CVE-2013-2094");
  script_bugtraq_id(59846);
  script_osvdb_id(93361);
  script_xref(name:"ALAS", value:"2013-190");
  script_xref(name:"CERT", value:"774103");
  script_xref(name:"EDB-ID", value:"25444");
  script_xref(name:"EDB-ID", value:"26131");

  script_name(english:"Amazon Linux AMI : kernel Privilege Escalation (ALAS-2013-190)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A flaw was found in the way index into perf_swevent_enabled array was
sanitized. A local, unprivileged user could leverage this flaw to gain
elevated privileges on the system."
  );
  # http://aws.amazon.com/amazon-linux-ami/security-bulletins/ALAS-2013-190/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa2ce384"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Run 'yum update kernel' to update the system. A reboot will be
necessary for the new kernel to be loaded."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
# kernel-docs skipped, rpm_check ignores it
if (rpm_check(release:"ALA", reference:"kernel-3.4.43-0.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.4.43-0.0.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.4.43-0.0.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.4.43-0.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.4.43-0.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.4.43-0.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.4.43-0.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.4.43-0.0.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0)
  {
    # Disassemble and reassemble rpm_report_get(), the fix version is releases higher than the affected versions
    curr_report = rpm_report_get();
    lines = split(curr_report, sep:'\n', keep:0);
    new_report = "";
    foreach currline (lines)
    {
      new_report += str_replace(
        find:"-3.4.43-0.0.amzn1",
        replace:"-3.4.43-43.43.amzn1",
        string:currline) + '\n';
    }

    security_hole(port:0, extra:new_report);
  }
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
