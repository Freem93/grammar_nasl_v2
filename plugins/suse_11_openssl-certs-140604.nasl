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
  script_id(76106);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/18 10:46:16 $");

  script_name(english:"SuSE 11.3 Security Update : openssl-certs (SAT Patch Number 9341)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"openssl-certs has been updated to include four new and remove two
certificates :

  - new:
    Atos_TrustedRoot_2011:2.8.92.51.203.98.44.95.179.50.crt

  - new:
    E-Tugra_Certification_Authority:2.8.106.104.62.156.81.15
    5.203.83.crt

  - new:
    TeliaSonera_Root_CA_v1:2.17.0.149.190.22.160.247.46.70.2
    41.123.57.130.114.250.139.205.150.crt

  - new: T-TeleSec_GlobalRoot_Class_2:2.1.1.crt

  - removed: Firmaprofesional_Root_CA:2.1.1.crt

  - removed: TDC_OCES_Root_CA:2.4.62.72.189.196.crt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881241"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9341.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl-certs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");
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

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"openssl-certs-1.97-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"openssl-certs-1.97-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openssl-certs-1.97-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
