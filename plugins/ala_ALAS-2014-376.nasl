#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-376.
#

include("compat.inc");

if (description)
{
  script_id(78319);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-0240", "CVE-2014-0242");
  script_xref(name:"ALAS", value:"2014-376");

  script_name(english:"Amazon Linux AMI : mod_wsgi (ALAS-2014-376)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that mod_wsgi did not properly drop privileges if the
call to setuid() failed. If mod_wsgi was set up to allow unprivileged
users to run WSGI applications, a local user able to run a WSGI
application could possibly use this flaw to escalate their privileges
on the system. Note: mod_wsgi is not intended to provide privilege
separation for WSGI applications. Systems relying on mod_wsgi to limit
or sandbox the privileges of mod_wsgi applications should migrate to a
different solution with proper privilege separation.

mod_wsgi allows you to host Python applications on the Apache HTTP
Server. It was found that a remote attacker could leak portions of a
mod_wsgi application's memory via the Content-Type header."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-376.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mod_wsgi' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_wsgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
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
if (rpm_check(release:"ALA", reference:"mod_wsgi-3.2-6.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_wsgi-debuginfo-3.2-6.8.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_wsgi / mod_wsgi-debuginfo");
}
