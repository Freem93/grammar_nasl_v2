#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0053.
#

include("compat.inc");

if (description)
{
  script_id(99080);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2015-8325");
  script_osvdb_id(137226);

  script_name(english:"OracleVM 3.3 / 3.4 : openssh (OVMSA-2017-0053)");
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

  - Allow to use ibmca crypto hardware (#1397547)

  - CVE-2015-8325: privilege escalation via user's PAM
    environment and UseLogin=yes (1405374)

  - Fix missing hmac-md5-96 from server offer (#1373836)

  - Prevent infinite loop when Ctrl+Z pressed at password
    prompt (#1218424)

  - Remove RC4 cipher and MD5 based MAC from the default
    client proposal (#1373836)

  - Resolve sftp force permission colision with umask
    (#1341747)

  - Relax bits needed check to allow hmac-sha2-512 with
    gss-group1-sha1- (#1353359)

  - close ControlPersist background process stderr when not
    in debug mode (#1335539)

  - Do not add a message 'The agent has no identities.' in
    ~/.ssh/authorized_keys (#1353410)

  - ssh-copy-id: SunOS does not understand ~ (#1327547)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000668.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?854d27aa"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000663.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90daf6f4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssh / openssh-clients / openssh-server
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-server");
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
if (rpm_check(release:"OVS3.3", reference:"openssh-5.3p1-122.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"openssh-clients-5.3p1-122.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"openssh-server-5.3p1-122.el6")) flag++;

if (rpm_check(release:"OVS3.4", reference:"openssh-5.3p1-122.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"openssh-clients-5.3p1-122.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"openssh-server-5.3p1-122.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-server");
}
