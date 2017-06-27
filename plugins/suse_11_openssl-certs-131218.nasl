#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71836);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/07 11:47:00 $");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : openssl-certs (SAT Patch Numbers 8681 / 8682)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"openssl-certs was updated with the current certificate data available
from mozilla.org.

Changes :

  - Updated certificates to revision 1.95 Distrust a sub-ca
    that issued google.com certificates. 'Distrusted AC DG
    Tresor SSL'. (bnc#854367)

Many CA updates from Mozilla :

  - new:
    CA_Disig_Root_R1:2.9.0.195.3.154.238.80.144.110.40.crt
    server auth, code signing, email signing

  - new:
    CA_Disig_Root_R2:2.9.0.146.184.136.219.176.138.193.99.cr
    t server auth, code signing, email signing

  - new:
    China_Internet_Network_Information_Center_EV_Certificate
    s_Root:2.4.72.159.0.1.crt server auth

  - changed:
    Digital_Signature_Trust_Co._Global_CA_1:2.4.54.112.21.15
    0.crt removed code signing and server auth abilities

  - changed:
    Digital_Signature_Trust_Co._Global_CA_3:2.4.54.110.211.2
    06.crt removed code signing and server auth abilities

  - new: D-TRUST_Root_Class_3_CA_2_2009:2.3.9.131.243.crt
    server auth

  - new: D-TRUST_Root_Class_3_CA_2_EV_2009:2.3.9.131.244.crt
    server auth

  - removed:
    Entrust.net_Premium_2048_Secure_Server_CA:2.4.56.99.185.
    102.crt

  - new:
    Entrust.net_Premium_2048_Secure_Server_CA:2.4.56.99.222.
    248.crt

  - removed:
    Equifax_Secure_eBusiness_CA_2:2.4.55.112.207.181.crt

  - new: PSCProcert:2.1.11.crt server auth, code signing,
    email signing

  - new:
    Swisscom_Root_CA_2:2.16.30.158.40.232.72.242.229.239.195
    .124.74.30.90.24.103.182.crt server auth, code signing,
    email signing

  - new:
    Swisscom_Root_EV_CA_2:2.17.0.242.250.100.226.116.99.211.
    141.253.16.29.4.31.118.202.88.crt server auth, code
    signing

  - changed:
    TC_TrustCenter_Universal_CA_III:2.14.99.37.0.1.0.2.20.14
    1.51.21.2.228.108.244.crt removed all abilities

  - new:
    TURKTRUST_Certificate_Services_Provider_Root_2007:2.1.1.
    crt server auth, code signing

  - changed: TWCA_Root_Certification_Authority:2.1.1.crt
    added code signing ability

  - new 'EE Certification Centre Root CA'

  - new 'T-TeleSec GlobalRoot Class 3'

  - revoke mis-issued intermediate CAs from TURKTRUST."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854367"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8681 / 8682 as appropriate."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl-certs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"openssl-certs-1.95-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"openssl-certs-1.95-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"openssl-certs-1.95-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"openssl-certs-1.95-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"openssl-certs-1.95-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openssl-certs-1.95-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
