#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60785);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2560", "CVE-2009-2562", "CVE-2009-2563", "CVE-2009-3550", "CVE-2009-3829", "CVE-2009-4377", "CVE-2010-0304");

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
"An invalid pointer dereference flaw was found in the Wireshark SMB and
SMB2 dissectors. If Wireshark read a malformed packet off a network or
opened a malicious dump file, it could crash or, possibly, execute
arbitrary code as the user running Wireshark. (CVE-2009-4377)

Several buffer overflow flaws were found in the Wireshark LWRES
dissector. If Wireshark read a malformed packet off a network or
opened a malicious dump file, it could crash or, possibly, execute
arbitrary code as the user running Wireshark. (CVE-2010-0304)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2009-2560,
CVE-2009-2562, CVE-2009-2563, CVE-2009-3550, CVE-2009-3829)

All running instances of Wireshark must be restarted for the update to
take effect.

Note: libsmi was added to SL4 and SL5 because it was a new dependency
for wireshark and older versions of SL4 and SL5 did not have libsmi."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=2022
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2995e64"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/20");
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
if (rpm_check(release:"SL3", reference:"wireshark-1.0.11-EL3.6")) flag++;
if (rpm_check(release:"SL3", reference:"wireshark-gnome-1.0.11-EL3.6")) flag++;

if (rpm_check(release:"SL4", reference:"libsmi-0.4.5-5.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libsmi-devel-0.4.5-5.el4")) flag++;
if (rpm_check(release:"SL4", reference:"wireshark-1.0.11-1.el4_8.5")) flag++;
if (rpm_check(release:"SL4", reference:"wireshark-gnome-1.0.11-1.el4_8.5")) flag++;

if (rpm_check(release:"SL5", reference:"libsmi-0.4.5-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libsmi-devel-0.4.5-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-1.0.11-1.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-gnome-1.0.11-1.el5_5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
