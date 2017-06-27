#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-775.
#

include("compat.inc");

if (description)
{
  script_id(95895);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/16 14:23:20 $");

  script_cve_id("CVE-2016-0718");
  script_xref(name:"ALAS", value:"2016-775");
  script_xref(name:"RHSA", value:"2016:2824");

  script_name(english:"Amazon Linux AMI : expat (ALAS-2016-775)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-0718 : Out-of-bounds read flaw

An out-of-bounds read flaw was found in the way Expat processed
certain input.

A remote attacker could send specially crafted XML that, when parsed
by an

application using the Expat library, would cause that application to
crash or,

possibly, execute arbitrary code with the permission of the user
running the

application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-775.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update expat' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:expat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:expat-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"expat-2.1.0-10.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"expat-debuginfo-2.1.0-10.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"expat-devel-2.1.0-10.21.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "expat / expat-debuginfo / expat-devel");
}
