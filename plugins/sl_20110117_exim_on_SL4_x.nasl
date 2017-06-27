#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60936);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/12 15:42:20 $");

  script_cve_id("CVE-2010-4345");

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
"A privilege escalation flaw was discovered in Exim. If an attacker
were able to gain access to the 'exim' user, they could cause Exim to
execute arbitrary commands as the root user. (CVE-2010-4345)

This update adds a new configuration file,
'/etc/exim/trusted-configs'. To prevent Exim from running arbitrary
commands as root, Exim will now drop privileges when run with a
configuration file not listed as trusted. This could break backwards
compatibility with some Exim configurations, as the trusted-configs
file only trusts '/etc/exim/exim.conf' and '/etc/exim/exim4.conf' by
default. If you are using a configuration file not listed in the new
trusted-configs file, you will need to add it manually.

Additionally, Exim will no longer allow a user to execute exim as root
with the -D command line option to override macro definitions. All
macro definitions that require root permissions must now reside in a
trusted configuration file.

After installing this update, the exim daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1101&L=scientific-linux-errata&T=0&P=655
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8c0b5a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/17");
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
if (rpm_check(release:"SL4", reference:"exim-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.3")) flag++;

if (rpm_check(release:"SL5", reference:"exim-4.63-5.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"exim-mon-4.63-5.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"exim-sa-4.63-5.el5_6.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
