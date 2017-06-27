#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61303);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2011-1143", "CVE-2011-1590", "CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175", "CVE-2011-2597", "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-1595");

  script_name(english:"Scientific Linux Security Update : wireshark on SL6.x i386/x86_64");
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
"Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

Several flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2011-1590, CVE-2011-4102, CVE-2012-1595)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2011-1143,
CVE-2011-1957, CVE-2011-1958, CVE-2011-1959, CVE-2011-2174,
CVE-2011-2175, CVE-2011-2597, CVE-2011-2698, CVE-2012-0041,
CVE-2012-0042, CVE-2012-0067, CVE-2012-0066)

Users of Wireshark should upgrade to these updated packages, which
contain backported patches to correct these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=1614
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?303e3ac9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/23");
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
if (rpm_check(release:"SL6", reference:"wireshark-1.2.15-2.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-debuginfo-1.2.15-2.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-devel-1.2.15-2.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-gnome-1.2.15-2.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
