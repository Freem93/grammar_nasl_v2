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
  script_id(81039);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");

  script_name(english:"SuSE 11 Security Update : glibc (SAT Patch Numbers 10202,10204,10206)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following security issue :

  - A vulnerability was found and fixed in the GNU C
    Library, specifically in the function gethostbyname(),
    that can lead to a local or remote buffer overflow.
    (bsc#913646). (CVE-2015-0235)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=913646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0235.html"
  );
  script_set_attribute(attribute:"solution", value:"
Apply the correct SAT patch number for your operating system :
SLES11 SP1: 10202
SLES11 SP2: 10204
SLED/SLES11 SP3: 10206");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
# 11.1
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-devel-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-html-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-i18ndata-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-info-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-locale-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"glibc-profile-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"nscd-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-32bit-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-devel-32bit-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-locale-32bit-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-profile-32bit-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-32bit-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.1-0.60.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"glibc-profile-32bit-2.11.1-0.60.1")) flag++;

# 11.2
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-devel-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-html-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-i18ndata-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-info-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-locale-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"glibc-profile-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"nscd-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-32bit-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.45.55.5")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.45.55.5")) flag++;

# 11.3
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-devel-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-i18ndata-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"glibc-locale-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"nscd-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i686", reference:"glibc-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i686", reference:"glibc-devel-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-devel-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-i18ndata-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-locale-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"nscd-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-devel-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-html-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-i18ndata-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-info-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-locale-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"glibc-profile-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"nscd-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.74.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.74.13")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
