#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-254.
#

include("compat.inc");

if (description)
{
  script_id(71270);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2013-4566");
  script_xref(name:"ALAS", value:"2013-254");
  script_xref(name:"RHSA", value:"2013:1779");

  script_name(english:"Amazon Linux AMI : mod24_nss (ALAS-2013-254)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way mod_nss handled the NSSVerifyClient
setting for the per-directory context. When configured to not require
a client certificate for the initial connection and only require it
for a specific directory, mod_nss failed to enforce this requirement
and allowed a client to access the directory when no valid client
certificate was provided. (CVE-2013-4566)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-254.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mod24_nss' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"mod24_nss-1.0.8-24.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_nss-debuginfo-1.0.8-24.17.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod24_nss / mod24_nss-debuginfo");
}
