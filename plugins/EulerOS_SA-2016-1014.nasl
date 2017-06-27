#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99777);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:26 $");

  script_cve_id(
    "CVE-2015-5370",
    "CVE-2016-2110",
    "CVE-2016-2111",
    "CVE-2016-2112",
    "CVE-2016-2113",
    "CVE-2016-2114",
    "CVE-2016-2115",
    "CVE-2016-2118"
  );
  script_osvdb_id(
    136339,
    136989,
    136990,
    136991,
    136992,
    136993,
    136994,
    136995
  );

  script_name(english:"EulerOS 2.0 SP1 : samba (EulerOS-SA-2016-1014)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Multiple flaws were found in Samba's DCE/RPC protocol
    implementation. A remote, authenticated attacker could
    use these flaws to cause a denial of service against
    the Samba server (high CPU load or a crash) or,
    possibly, execute arbitrary code with the permissions
    of the user running Samba (root). This flaw could also
    be used to downgrade a secure DCE/RPC connection by a
    man-in-the-middle attacker taking control of an Active
    Directory (AD) object and compromising the security of
    a Samba Active Directory Domain Controller
    (DC).(CVE-2015-5370)

  - A protocol flaw, publicly referred to as Badlock, was
    found in the Security Account Manager Remote Protocol
    (MS-SAMR) and the Local Security Authority (Domain
    Policy) Remote Protocol (MS-LSAD). Any authenticated
    DCE/RPC connection that a client initiates against a
    server could be used by a man-in-the-middle attacker to
    impersonate the authenticated user against the SAMR or
    LSA service on the server.

  - As a result, the attacker would be able to get
    read/write access to the Security Account Manager
    database, and use this to reveal all passwords or any
    other potentially sensitive information in that
    database. (CVE-2016-2118)

  - Several flaws were found in Samba's implementation of
    NTLMSSP authentication. An nauthenticated,
    man-in-the-middle attacker could use this flaw to clear
    the encryption and integrity flags of a connection,
    causing data to be transmitted in plain text. The
    attacker could also force the client or server into
    sending data in plain text even if encryption was
    explicitly requested for that
    connection.(CVE-2016-2110)

  - It was discovered that Samba configured as a Domain
    Controller would establish a secure communication
    channel with a machine using a spoofed computer name. A
    remote attacker able to observe network traffic could
    use this flaw to obtain session-related information
    about the spoofed machine. (CVE-2016-2111)

  - It was found that Samba's LDAP implementation did not
    enforce integrity protection for LDAP connections. A
    man-in-the-middle attacker could use this flaw to
    downgrade LDAP connections to use no integrity
    protection, allowing them to hijack such
    connections.(CVE-2016-2112)

  - It was found that Samba did not validate SSL/TLS
    certificates in certain connections. A
    man-in-the-middle attacker could use this flaw to spoof
    a Samba server using a specially crafted SSL/TLS
    certificate.(CVE-2016-2113)

  - It was discovered that Samba did not enforce Server
    Message Block (SMB) signing for clients using the SMB1
    protocol. A man-in-the-middle attacker could use this
    flaw to modify traffic between a client and a server.
    (CVE-2016-2114)

  - It was found that Samba did not enable integrity
    protection for IPC traffic by default. A
    man-in-the-middle attacker could use this flaw to view
    and modify the data sent between a Samba server and a
    client.(CVE-2016-2115)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1014
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0bbec453");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pytalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-tdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-tevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["libldb-1.1.25-1",
        "libsmbclient-4.2.10-6",
        "libtalloc-2.1.5-1",
        "libtdb-1.3.8-1",
        "libtevent-0.9.26-1",
        "libwbclient-4.2.10-6",
        "pytalloc-2.1.5-1",
        "python-tdb-1.3.8-1",
        "python-tevent-0.9.26-1",
        "samba-4.2.10-6",
        "samba-client-4.2.10-6",
        "samba-client-libs-4.2.10-6",
        "samba-common-4.2.10-6",
        "samba-common-libs-4.2.10-6",
        "samba-common-tools-4.2.10-6",
        "samba-libs-4.2.10-6",
        "samba-python-4.2.10-6",
        "samba-winbind-4.2.10-6",
        "samba-winbind-clients-4.2.10-6",
        "samba-winbind-modules-4.2.10-6",
        "tdb-tools-1.3.8-1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
