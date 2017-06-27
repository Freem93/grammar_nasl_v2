#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-294.
#

include("compat.inc");

if (description)
{
  script_id(72750);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2013-4449");
  script_xref(name:"ALAS", value:"2014-294");

  script_name(english:"Amazon Linux AMI : openldap (ALAS-2014-294)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The rwm overlay in OpenLDAP 2.4.23, 2.4.36, and earlier does not
properly count references, which allows remote attackers to cause a
denial of service (slapd crash) by unbinding immediately after a
search request, which triggers rwm_conn_destroy to free the session
context while it is being used by rwm_op_search."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-294.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openldap' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openldap-2.4.23-34.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-clients-2.4.23-34.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-debuginfo-2.4.23-34.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-devel-2.4.23-34.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-servers-2.4.23-34.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-servers-sql-2.4.23-34.23.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-debuginfo / openldap-devel / etc");
}
