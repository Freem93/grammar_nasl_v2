#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(77865);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/12/03 05:41:04 $");

  script_cve_id("CVE-2014-6271");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"Scientific Linux Security Update : bash on SL5.x, SL6.x i386/x86_64 (Shellshock)");
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
"A flaw was found in the way Bash evaluated certain specially crafted
environment variables. An attacker could use this flaw to override or
bypass environment restrictions to execute shell commands. Certain
services and applications allow remote unauthenticated attackers to
provide environment variables, allowing them to exploit this issue.
(CVE-2014-6271)

For additional information on the CVE-2014-6271 flaw, refer to
https://securityblog.redhat.com/2014/09/24/bash-specially
crafted-environment-variables-code-injection-attack/"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1409&L=scientific-linux-errata&T=0&P=1727
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfda4a81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bash, bash-debuginfo and / or bash-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"bash-3.2-33.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"bash-debuginfo-3.2-33.el5.1")) flag++;

if (rpm_check(release:"SL6", reference:"bash-4.1.2-15.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"bash-debuginfo-4.1.2-15.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"bash-doc-4.1.2-15.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
