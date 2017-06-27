#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0010.
#

include("compat.inc");

if (description)
{
  script_id(79457);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2008-3651", "CVE-2008-3652", "CVE-2009-1574", "CVE-2009-1632");
  script_bugtraq_id(30657, 34765);
  script_osvdb_id(54286, 56400, 56401);

  script_name(english:"OracleVM 2.1 : ipsec-tools (OVMSA-2009-0010)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

CVE-2009-1574 racoon/isakmp_frag.c in ipsec-tools before 0.7.2 allows
remote attackers to cause a denial of service (crash) via crafted
fragmented packets without a payload, which triggers a NULL pointer
dereference.

CVE-2009-1632 Multiple memory leaks in Ipsec-tools before 0.7.2 allow
remote attackers to cause a denial of service (memory consumption) via
vectors involving (1) signature verification during user
authentication with X.509 certificates, related to the
eay_check_x509sign function in src/racoon/crypto_openssl.c  and (2)
the NAT-Traversal (aka NAT-T) keepalive implementation, related to
src/racoon/nattraversal.c.

CVE-2008-3651 Memory leak in racoon/proposal.c in the racoon daemon in
ipsec-tools before 0.7.1 allows remote authenticated users to cause a
denial of service (memory consumption) via invalid proposals.

CVE-2008-3652 src/racoon/handler.c in racoon in ipsec-tools does not
remove an 'orphaned ph1' (phase 1) handle when it has been initiated
remotely, which allows remote attackers to cause a denial of service
(resource consumption).

  - fix nul dereference in frag code and some memory leaks
    (#497990)

  - also do not destroy ports in ph2 (#231604)

  - improved fix for cleanup of IPSEC SAs in SADB (#231604)

  - fix cleanup of IPSEC SAs in SADB (#231604)

  - fix segfault in timer (#378551)

  - handle new interfaces immediately (#247301)

  - eliminate debug logging overhead when log level is lower
    (#248567)

  - use the adminsock_path as specified on the command line
    (#247294)

  - link only necessary libraries (#458631)

  - make racoon PIE executable (#210023)

  - fix for DoS through various memory leaks (CVE-2008-3651
    #456660, CVE-2008-3652 #458846)

  - use the current kernel headers instead of the private
    copy (#446979)

  - Resolves: rhbz#435803 - update pfkeyv2.h with new
    #defines"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2009-May/000025.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ipsec-tools package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"ipsec-tools-0.6.5-13.el5_3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipsec-tools");
}
