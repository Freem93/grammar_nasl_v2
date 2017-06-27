#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0030.
#

include("compat.inc");

if (description)
{
  script_id(89020);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2010-5107");
  script_bugtraq_id(58162);
  script_osvdb_id(90007);

  script_name(english:"OracleVM 3.2 : openssh (OVMSA-2016-0030)");
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

  - change default value of MaxStartups - CVE-2010-5107
    (John Haxby) 

  - improve RNG seeding from /dev/random (#681291,#708056)

  - make ssh(1)'s ConnectTimeout option apply to both the
    TCP connection and SSH banner exchange (#750725)

  - use IPV6_V6ONLY for sshd inet6 listening socket
    (#640857)

  - add LANGUAGE to the sent/accepted evvironment (#710229)

  - ssh-copy-id copies now id_rsa.pub by default (#731930)

  - repairs man pages (#731925)

  - set cloexec on accept socket (#642935)

  - add umask to sftp (#720598)

  - enable lastolg for big uids (#706315)

  - enable selinux domain transition to passwd_t (#689406)

  - enable pubkey auth in the fips mode (#674747)

  - improve resseding the prng from /dev/urandom or
    /dev/random respectively (#681291)

  - periodically ressed the prng from /dev/urandom or
    /dev/random respectively (#681291)

  - change cipher preferences (#661716)

  - change cipher preferences (#661716)

  - enable to run sshd as non root user (#661669)

  - reenable rekeying (#659242)

  - add nss keys to key audit patch (#632402)

  - key audit patch (#632402)

  - supply forced command documentation (#532559)

  - compile in the OpenSSL engine support

  - record lastlog with big uid (#616396)

  - add OpenSSL engine support (#594815)

  - backport forced command directive (#532559)

  - stderr does not more disturb sftp (#576765)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-February/000420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41282881"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssh / openssh-clients / openssh-server
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"openssh-4.3p2-82.0.1.el5")) flag++;
if (rpm_check(release:"OVS3.2", reference:"openssh-clients-4.3p2-82.0.1.el5")) flag++;
if (rpm_check(release:"OVS3.2", reference:"openssh-server-4.3p2-82.0.1.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-server");
}
