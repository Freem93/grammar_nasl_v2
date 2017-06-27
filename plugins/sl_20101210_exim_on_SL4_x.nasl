#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60919);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/12 15:42:20 $");

  script_cve_id("CVE-2010-4344");

  script_name(english:"Scientific Linux Security Update : exim on SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was discovered in Exim's internal
string_vformat() function. A remote attacker could use this flaw to
execute arbitrary code on the mail server running Exim.
(CVE-2010-4344)

Note: successful exploitation would allow a remote attacker to execute
arbitrary code as root on a Scientific Linux 4 or 5 system that is
running the Exim mail server. An exploit for this issue is known to
exist.

After installing this update, the Exim daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1012&L=scientific-linux-errata&T=0&P=1056
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cab787a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"exim-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"exim-4.63-5.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"exim-mon-4.63-5.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"exim-sa-4.63-5.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
