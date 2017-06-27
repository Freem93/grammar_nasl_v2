#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-738.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93016);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:42 $");

  script_cve_id("CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0651", "CVE-2016-0666", "CVE-2016-2047", "CVE-2016-3452", "CVE-2016-3477", "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440", "CVE-2016-5444");
  script_xref(name:"ALAS", value:"2016-738");

  script_name(english:"Amazon Linux AMI : mysql55 (ALAS-2016-738)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the MariaDB client library did not properly check
host names against server identities noted in the X.509 certificates
when establishing secure connections using TLS/SSL. A
man-in-the-middle attacker could possibly use this flaw to impersonate
a server to a client. (CVE-2016-2047)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via vectors related
to UDF. (CVE-2016-0608)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to privileges. (CVE-2016-0609)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Options. (CVE-2016-0505)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to InnoDB. (CVE-2016-0600)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Optimizer. (CVE-2016-0616)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows
remote attackers to affect confidentiality via vectors related to
Server: Security: Encryption. (CVE-2016-3452)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows
local users to affect availability via vectors related to DDL.
(CVE-2016-0644)

Unspecified vulnerability in Oracle MySQL 5.5.49 and earlier allows
local users to affect confidentiality, integrity, and availability via
vectors related to Server: Parser. (CVE-2016-3477)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via vectors related
to DML. (CVE-2016-0596)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via unknown vectors
related to Optimizer. (CVE-2016-0597)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows
local users to affect integrity and availability via vectors related
to DML. (CVE-2016-0640)

Unspecified vulnerability in Oracle MySQL 5.5.49 and earlier allows
remote authenticated users to affect availability via vectors related
to Server: Types. (CVE-2016-3521)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows
local users to affect integrity and availability via vectors related
to Federated. (CVE-2016-0642)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows
local users to affect confidentiality via vectors related to DML.
(CVE-2016-0643)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows
local users to affect availability via vectors related to Security:
Privileges. (CVE-2016-0666)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
local users to affect availability via vectors related to Optimizer.
(CVE-2016-0651)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows
local users to affect availability via vectors related to Replication.
(CVE-2016-0650)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect availability via vectors related
to DML. (CVE-2016-0598)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows
local users to affect availability via vectors related to PS.
(CVE-2016-0649)

Unspecified vulnerability in Oracle MySQL 5.5.49 and earlier allows
remote administrators to affect availability via vectors related to
Server: RBR. (CVE-2016-5440)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows
remote attackers to affect confidentiality via vectors related to
Server: Connection. (CVE-2016-5444)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
remote authenticated users to affect integrity via unknown vectors
related to encryption. (CVE-2016-0606)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows
local users to affect availability via vectors related to PS.
(CVE-2016-0648)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows
local users to affect availability via vectors related to DML.
(CVE-2016-0646)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows
local users to affect confidentiality, integrity, and availability via
unknown vectors related to Client. (CVE-2016-0546)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows
local users to affect availability via vectors related to FTS.
(CVE-2016-0647)

Unspecified vulnerability in Oracle MySQL 5.5.49 and earlier allows
remote authenticated users to affect availability via vectors related
to Server: DML. (CVE-2016-3615)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows
local users to affect confidentiality and availability via vectors
related to MyISAM. (CVE-2016-0641)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-738.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql55' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/18");
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
if (rpm_check(release:"ALA", reference:"mysql-config-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-bench-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-debuginfo-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-devel-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-devel-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-libs-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-server-5.5.51-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-test-5.5.51-1.11.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-config / mysql55 / mysql55-bench / mysql55-debuginfo / etc");
}
