#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55981);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:46:54 $");

  script_cve_id("CVE-2004-0801", "CVE-2011-2697");

  script_name(english:"SuSE 11.1 Security Update : hplip (SAT Patch Number 4989)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of hplip fixes :

  - This patch originally affected foomatic-rip in CUPS but
    was found to be in foomatic-rip-hplip too.
    (CVE-2004-0801: CVSS v2 Base Score: 7.5
    (AV:N/AC:L/Au:N/C:P/I:P/A:P))

  - The foomatic print filters of the hplip package
    contained a remote code execution vulnerability. Remote
    users, if allowed to access a print server such as CUPS,
    could execute arbitrary commands as lp system user.
    (CVE-2011-2697: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P))"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=59233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2004-0801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2697.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4989.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hplip-hpijs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hplip-3.9.8-3.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hplip-hpijs-3.9.8-3.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hplip-3.9.8-3.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hplip-hpijs-3.9.8-3.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"hplip-3.9.8-3.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"hplip-hpijs-3.9.8-3.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
