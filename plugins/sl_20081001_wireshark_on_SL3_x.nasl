#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60479);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-1070", "CVE-2008-1071", "CVE-2008-1072", "CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563", "CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933", "CVE-2008-3934");

  script_name(english:"Scientific Linux Security Update : wireshark on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Multiple buffer overflow flaws were found in Wireshark. If Wireshark
read a malformed packet off a network, it could crash or, possibly,
execute arbitrary code as the user running Wireshark. (CVE-2008-3146)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malformed dump file. (CVE-2008-1070,
CVE-2008-1071, CVE-2008-1072, CVE-2008-1561, CVE-2008-1562,
CVE-2008-1563, CVE-2008-3137, CVE-2008-3138, CVE-2008-3141,
CVE-2008-3145, CVE-2008-3932, CVE-2008-3933, CVE-2008-3934)

Additionally, this update changes the default Pluggable Authentication
Modules (PAM) configuration to always prompt for the root password
before each start of Wireshark. This avoids unintentionally running
Wireshark with root privileges."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0810&L=scientific-linux-errata&T=0&P=384
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5599e01e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark and / or wireshark-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"wireshark-1.0.3-EL3.3")) flag++;
if (rpm_check(release:"SL3", reference:"wireshark-gnome-1.0.3-EL3.3")) flag++;

if (rpm_check(release:"SL4", reference:"wireshark-1.0.3-3.el4_7")) flag++;
if (rpm_check(release:"SL4", reference:"wireshark-gnome-1.0.3-3.el4_7")) flag++;

if (rpm_check(release:"SL5", reference:"wireshark-1.0.3-4.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-gnome-1.0.3-4.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
