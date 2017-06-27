#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0059.
#

include("compat.inc");

if (description)
{
  script_id(99113);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/04 13:36:41 $");

  script_cve_id("CVE-2017-2628");
  script_osvdb_id(154631);

  script_name(english:"OracleVM 3.3 / 3.4 : curl (OVMSA-2017-0059)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - treat Negotiate authentication as connection-oriented
    (CVE-2017-2628)

  - fix a bug in DNS caching code that causes a memory leak
    (#1302893)

  - SSH: make CURLOPT_SSH_PUBLIC_KEYFILE treat '' as NULL
    (#1260742)

  - use the default min/max TLS version provided by NSS
    (#1289205)

  - prevent NSS from incorrectly re-using a session
    (#1269660)

  - prevent test46 from failing due to expired cookie
    (#1277551)

  - SSH: do not require public key file for user
    authentication (#1260742)

  - make SCP/SFTP work with --proxytunnel (#1258566)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000672.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f34b236"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000673.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab354e79"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected curl / libcurl packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"curl-7.19.7-53.el6_9")) flag++;
if (rpm_check(release:"OVS3.3", reference:"libcurl-7.19.7-53.el6_9")) flag++;

if (rpm_check(release:"OVS3.4", reference:"curl-7.19.7-53.el6_9")) flag++;
if (rpm_check(release:"OVS3.4", reference:"libcurl-7.19.7-53.el6_9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl");
}
