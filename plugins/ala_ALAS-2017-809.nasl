#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-809.
#

include("compat.inc");

if (description)
{
  script_id(99036);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2017-5953", "CVE-2017-6349", "CVE-2017-6350");
  script_xref(name:"ALAS", value:"2017-809");

  script_name(english:"Amazon Linux AMI : vim (ALAS-2017-809)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow flaw was found in the way vim handled tree length
values when reading an undo file. This bug could result in vim
crashing when trying to process corrupted undo files. (CVE-2017-6350)

An integer overflow flaw was found in the way vim handled undo files.
This bug could result in vim crashing when trying to process corrupted
undo files.(CVE-2017-6349)

vim before patch 8.0.0322 does not properly validate values for tree
length when handling a spell file, which may result in an integer
overflow at a memory allocation site and a resultant buffer overflow.
(CVE-2017-5953)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-809.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update vim' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"vim-common-8.0.0503-1.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-debuginfo-8.0.0503-1.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-enhanced-8.0.0503-1.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-filesystem-8.0.0503-1.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-minimal-8.0.0503-1.45.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-common / vim-debuginfo / vim-enhanced / vim-filesystem / etc");
}
