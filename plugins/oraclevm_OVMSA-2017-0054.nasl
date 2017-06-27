#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0054.
#

include("compat.inc");

if (description)
{
  script_id(99081);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337");
  script_osvdb_id(149952, 149953, 149954);

  script_name(english:"OracleVM 3.3 / 3.4 : gnutls (OVMSA-2017-0054)");
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

  - Upgraded to 2.12.23 to incorporate multiple TLS 1.2
    fixes (#1326389, #1326073, #1323215, #1320982, #1328205,
    #1321112)

  - Modified gnutls-serv to accept --sni-hostname (#1333521)

  - Modified gnutls-serv to always reply with an alert
    message (#1327656)

  - Removed support for DSA2 as it causes interoperability
    issues (#1321112)

  - Allow sending and receiving certificates which were not
    in the signature algorithms extension (#1328205)

  - Removed support for EXPORT ciphersuites (#1337460)

  - Raised the minimum acceptable DH size to 1024 (#1335924)

  - Restricted the number of alert that can be received
    during handshake (#1388730)

  - Added fixes for OpenPGP parsing issues (CVE-2017-5337,
    CVE-2017-5336, CVE-2017-5335)

  - The exposed (but internal) crypto back-end registration
    API is deprecated and no longer functional. The ABI is
    kept compatible (#1415682)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?656eaa25"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6fc511e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls / gnutls-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
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
if (rpm_check(release:"OVS3.3", reference:"gnutls-2.12.23-21.el6")) flag++;

if (rpm_check(release:"OVS3.4", reference:"gnutls-2.12.23-21.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"gnutls-utils-2.12.23-21.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-utils");
}
