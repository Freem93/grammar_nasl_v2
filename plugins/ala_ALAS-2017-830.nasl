#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-830.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(100275);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/19 13:47:30 $");

  script_cve_id("CVE-2017-3265", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3450", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3461", "CVE-2017-3462", "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3599");
  script_xref(name:"ALAS", value:"2017-830");

  script_name(english:"Amazon Linux AMI : mysql56 (ALAS-2017-830)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Server: Security: Privileges unspecified vulnerability (CPU Apr 
2017) :

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Security: Privileges). Supported versions that
are affected are 5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and
earlier. Easily 'exploitable' vulnerability allows high privileged
attacker with network access via multiple protocols to compromise
MySQL Server. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
(CVE-2017-3462)

Security: Privileges unspecified vulnerability (CPU Apr 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Security: Privileges). Supported versions that
are affected are 5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and
earlier. Easily 'exploitable' vulnerability allows high privileged
attacker with network access via multiple protocols to compromise
MySQL Server. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
(CVE-2017-3463)

Server: Security: Privileges unspecified vulnerability (CPU Apr 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Security: Privileges). Supported versions that
are affected are 5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and
earlier. Easily 'exploitable' vulnerability allows high privileged
attacker with network access via multiple protocols to compromise
MySQL Server. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
(CVE-2017-3461)

Server: DDL unspecified vulnerability (CPU Apr 2017) :

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Supported versions that are affected are
5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and earlier. Easily
'exploitable' vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
update, insert or delete access to some of MySQL Server accessible
data. CVSS 3.0 Base Score 4.3 (Integrity impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N). (CVE-2017-3464)

Unsafe chmod/chown use in init script (CPU Jan 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Packaging). Supported versions that are
affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and
earlier. Difficult to exploit vulnerability allows high privileged
attacker with logon to the infrastructure where MySQL Server executes
to compromise MySQL Server. Successful attacks require human
interaction from a person other than the attacker. Successful attacks
of this vulnerability can result in unauthorized access to critical
data or complete access to all MySQL Server accessible data and
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. CVSS v3.0 Base Score 5.6
(Confidentiality and Availability impacts). (CVE-2017-3265)

Server: Optimizer unspecified vulnerability (CPU Apr 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and
earlier. Easily 'exploitable' vulnerability allows low privileged
attacker with network access via multiple protocols to compromise
MySQL Server. While the vulnerability is in MySQL Server, attacks may
significantly impact additional products. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0
Base Score 7.7 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H). (CVE-2017-3309)

Server: DML unspecified vulnerability (CPU Apr 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DML). Supported versions that are affected are
5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and earlier. Easily
'exploitable' vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
While the vulnerability is in MySQL Server, attacks may significantly
impact additional products. Successful attacks of this vulnerability
can result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
7.7 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H). (CVE-2017-3308)

Server: DML unspecified vulnerability (CPU Apr 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DML). Supported versions that are affected are
5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and earlier. Easily
'exploitable' vulnerability allows high privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
(CVE-2017-3456)

Server: Memcached unspecified vulnerability (CPU Apr 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Memcached). Supported versions that are
affected are 5.6.35 and earlier and 5.7.17 and earlier. Easily
'exploitable' vulnerability allows unauthenticated attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
(CVE-2017-3450)

Server: Optimizer unspecified vulnerability (CPU Apr 2017)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.54 and earlier, 5.6.35 and earlier and 5.7.17 and
earlier. Easily 'exploitable' vulnerability allows low privileged
attacker with network access via multiple protocols to compromise
MySQL Server. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
(CVE-2017-3453)

Integer underflow in get_56_lenc_string() leading to DoS (CPU Apr
2017) :

An integer overflow flaw leading to a buffer overflow was found in the
way MySQL parsed connection handshake packets. An unauthenticated
remote attacker with access to the MySQL port could use this flaw to
crash the mysqld daemon. (CVE-2017-3599)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-830.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/19");
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
if (rpm_check(release:"ALA", reference:"mysql56-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-bench-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-common-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-debuginfo-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-devel-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-devel-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-errmsg-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-libs-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-server-5.6.36-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-test-5.6.36-1.25.amzn1")) flag++;

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
