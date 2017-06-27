#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60486);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2006-7234", "CVE-2008-4690");

  script_name(english:"Scientific Linux Security Update : lynx on SL3.x, SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An arbitrary command execution flaw was found in the Lynx 'lynxcgi:'
URI handler. An attacker could create a web page redirecting to a
malicious URL that could execute arbitrary code as the user running
Lynx in the non-default 'Advanced' user mode. (CVE-2008-4690)

Note: In these updated lynx packages, Lynx will always prompt users
before loading a 'lynxcgi:' URI. Additionally, the default lynx.cfg
configuration file now marks all 'lynxcgi:' URIs as untrusted by
default.

A flaw was found in a way Lynx handled '.mailcap' and '.mime.types'
configuration files. Files in the browser's current working directory
were opened before those in the user's home directory. A local
attacker, able to convince a user to run Lynx in a directory under
their control, could possibly execute arbitrary commands as the user
running Lynx. (CVE-2006-7234)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0810&L=scientific-linux-errata&T=0&P=2192
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28be28ae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"lynx-2.8.5-11.3")) flag++;

if (rpm_check(release:"SL4", reference:"lynx-2.8.5-18.2.el4_7.1")) flag++;

if (rpm_check(release:"SL5", reference:"lynx-2.8.5-28.1.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
