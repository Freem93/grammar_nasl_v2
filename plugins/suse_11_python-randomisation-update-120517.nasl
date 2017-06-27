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
  script_id(64221);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:04 $");

  script_cve_id("CVE-2011-1015", "CVE-2011-1521", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150");

  script_name(english:"SuSE 11.1 Security Update : libpython2_6-1_0, libpython2_6-1_0-32bit, libpython2_6-1_0-x86, python, etc (SAT Patch Number 6310)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to python 2.6.8 fixes the following bugs, among others :

  - XMLRPC Server DoS. (CVE-2012-0845, bnc#747125)

  - hash randomization issues. (CVE-2012-1150, bnc#751718)

  - insecure creation of .pypirc. (CVE-2011-4944,
    bnc#754447)

  - SimpleHTTPServer XSS. (CVE-2011-1015, bnc#752375)

  - functions can accept unicode kwargs. (bnc#744287)

  - python MainThread lacks ident. (bnc#754547)

  - TypeError: waitpid() takes no keyword arguments.
    (bnc#751714)

  - Source code exposure in CGIHTTPServer module.
    (CVE-2011-1015, bnc#674646)

  - Insecure redirect processing in urllib2 (CVE-2011-1521,
    bnc#682554) The hash randomization fix is by default
    disabled to keep compatibility with existing python code
    when it extracts hashes.

To enable the hash seed randomization you can use: - pass -R to the
python interpreter commandline. - set the environment variable
PYTHONHASHSEED=random to enable it for programs. You can also set this
environment variable to a fixed hash seed by specifying a integer
value between 0 and MAX_UINT.

In generally enabling this is only needed when malicious third parties
can inject values into your hash tables.

The update to 2.6.8 also provides many compatibility fixes with
OpenStack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4944.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0845.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1150.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6310.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpython2_6-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libpython2_6-1_0-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"python-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"python-base-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"python-curses-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"python-devel-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"python-tk-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"python-xml-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"libpython2_6-1_0-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-base-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-curses-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-demo-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-doc-2.6-8.13.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-doc-pdf-2.6-8.13.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-gdbm-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-idle-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-tk-2.6.8-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"python-xml-2.6.8-0.13.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
