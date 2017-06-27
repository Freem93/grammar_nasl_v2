#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-684.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90366);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-4766", "CVE-2015-4791", "CVE-2015-4792", "CVE-2015-4800", "CVE-2015-4802", "CVE-2015-4807", "CVE-2015-4815", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4833", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4862", "CVE-2015-4864", "CVE-2015-4866", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4890", "CVE-2015-4895", "CVE-2015-4904", "CVE-2015-4905", "CVE-2015-4910", "CVE-2015-4913", "CVE-2015-7744", "CVE-2016-0502", "CVE-2016-0503", "CVE-2016-0504", "CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0594", "CVE-2016-0595", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0599", "CVE-2016-0600", "CVE-2016-0601", "CVE-2016-0605", "CVE-2016-0606", "CVE-2016-0607", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0610", "CVE-2016-0611", "CVE-2016-0616");
  script_xref(name:"ALAS", value:"2016-684");

  script_name(english:"Amazon Linux AMI : mysql56 (ALAS-2016-684)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wolfSSL (formerly CyaSSL) before 3.6.8 does not properly handle faults
associated with the Chinese Remainder Theorem (CRT) process when
allowing ephemeral key exchange without low memory optimizations on a
server, which makes it easier for remote attackers to obtain private
RSA keys by capturing TLS handshakes, also known as a Lenstra attack.
(CVE-2015-7744)

Unspecified vulnerability in Oracle MySQL Server 5.6.24 and earlier
allows remote authenticated users to affect integrity via unknown
vectors related to Server : Security : Privileges. (CVE-2015-4864)

Unspecified vulnerability in Oracle MySQL Server 5.6.23 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : InnoDB. (CVE-2015-4866)

Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier,
and 5.6.26 and earlier, allows remote authenticated users to affect
availability via unknown vectors related to Server : InnoDB.
(CVE-2015-4861)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via vectors
related to DML. (CVE-2015-4862)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Optimizer. (CVE-2016-0616)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : Memcached. (CVE-2015-4910)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via vectors
related to Server : DML, a different vulnerability than CVE-2015-4858
. (CVE-2015-4913)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to InnoDB. (CVE-2016-0610)

Unspecified vulnerability in Oracle MySQL 5.6.21 and earlier allows
remote authenticated users to affect availability via vectors related
to DML. (CVE-2016-0594)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via vectors related
to DML. (CVE-2016-0595)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via vectors related
to DML. (CVE-2016-0596)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Optimizer. (CVE-2016-0597)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via vectors related
to DML. (CVE-2016-0598)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : Partition, a different vulnerability than
CVE-2015-4802 . (CVE-2015-4792)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : Security : Privileges. (CVE-2015-4791)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier,
when running on Windows, allows remote authenticated users to affect
availability via unknown vectors related to Server : Query Cache.
(CVE-2015-4807)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier,
allows remote authenticated users to affect availability via unknown
vectors related to Server : Parser. (CVE-2015-4870)

Unspecified vulnerability in Oracle MySQL 5.7.9 allows remote
authenticated users to affect availability via unknown vectors related
to Optimizer. (CVE-2016-0599)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
local users to affect confidentiality, integrity, and availability via
unknown vectors related to Client. (CVE-2016-0546)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via vectors
related to DML, a different vulnerability than CVE-2015-4913 .
(CVE-2015-4858)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via vectors
related to Server : DDL. (CVE-2015-4815)

Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : Partition. (CVE-2015-4833)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect integrity via unknown
vectors related to Server : Security : Privileges. (CVE-2015-4830)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : SP. (CVE-2015-4836)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via vectors related
to UDF. (CVE-2016-0608)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to privileges. (CVE-2016-0609)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Options. (CVE-2016-0505)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via vectors related
to DML, a different vulnerability than CVE-2016-0503 . (CVE-2016-0504)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : Replication. (CVE-2015-4890)

Unspecified vulnerability in Oracle MySQL 5.7.9 allows remote
authenticated users to affect availability via unknown vectors related
to Partition. (CVE-2016-0601)

Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to libmysqld. (CVE-2015-4904)

Unspecified vulnerability in Oracle MySQL Server 5.6.23 and earlier
allows remote authenticated users to affect availability via vectors
related to Server : DML. (CVE-2015-4905)

Unspecified vulnerability in Oracle MySQL 5.6.26 and earlier allows
remote authenticated users to affect availability via unknown vectors.
(CVE-2016-0605)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect integrity via unknown vectors
related to encryption. (CVE-2016-0606)

Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier
allows local users to affect availability via unknown vectors related
to Server : Security : Firewall. (CVE-2015-4766)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Optimizer. (CVE-2016-0611)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to replication. (CVE-2016-0607)

Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier
allows local users to affect confidentiality, integrity, and
availability via unknown vectors related to Client programs.
(CVE-2015-4819)

Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier
allows remote authenticated users to affect confidentiality,
integrity, and availability via vectors related to DML.
(CVE-2015-4879)

Unspecified vulnerability in Oracle MySQL 5.6.11 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Optimizer. (CVE-2016-0502)

Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : InnoDB. (CVE-2015-4895)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via vectors related
to DML, a different vulnerability than CVE-2016-0504 . (CVE-2016-0503)

Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to InnoDB. (CVE-2016-0600)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : Partition, a different vulnerability than
CVE-2015-4792 . (CVE-2015-4802)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect availability via unknown
vectors related to Server : Optimizer. (CVE-2015-4800)

Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier
allows remote authenticated users to affect confidentiality via
unknown vectors related to Server : Types. (CVE-2015-4826)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-684.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
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
if (rpm_check(release:"ALA", reference:"mysql56-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-bench-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-common-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-debuginfo-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-devel-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-devel-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-errmsg-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-libs-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-server-5.6.29-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-test-5.6.29-1.14.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql56 / mysql56-bench / mysql56-common / mysql56-debuginfo / etc");
}
