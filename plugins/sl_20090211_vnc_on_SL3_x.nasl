#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60535);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-4770");

  script_name(english:"Scientific Linux Security Update : vnc on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"An insufficient input validation flaw was discovered in the VNC client
application, vncviewer. If an attacker could convince a victim to
connect to a malicious VNC server, or when an attacker was able to
connect to vncviewer running in the 'listen' mode, the attacker could
cause the victim's vncviewer to crash or, possibly, execute arbitrary
code. (CVE-2008-4770)

For the update to take effect, all running instances of vncviewer must
be restarted after the update is installed."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0902&L=scientific-linux-errata&T=0&P=1259
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f20f9e8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vnc and / or vnc-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/11");
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
if (rpm_check(release:"SL3", reference:"vnc-4.0-0.beta4.1.8")) flag++;
if (rpm_check(release:"SL3", reference:"vnc-server-4.0-0.beta4.1.8")) flag++;

if (rpm_check(release:"SL4", reference:"vnc-4.0-12.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"vnc-server-4.0-12.el4_7.1")) flag++;

if (rpm_check(release:"SL5", reference:"vnc-4.1.2-14.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"vnc-server-4.1.2-14.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
