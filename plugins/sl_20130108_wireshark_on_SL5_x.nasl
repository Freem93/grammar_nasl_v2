#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63606);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 14:07:22 $");

  script_cve_id("CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2175", "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-4285", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291");

  script_name(english:"Scientific Linux Security Update : wireshark on SL5.x i386/x86_64");
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
"A heap-based buffer overflow flaw was found in the way Wireshark
handled Endace ERF (Extensible Record Format) capture files. If
Wireshark opened a specially- crafted ERF capture file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2011-4102)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2011-1958,
CVE-2011-1959, CVE-2011-2175, CVE-2011-2698, CVE-2012-0041,
CVE-2012-0042, CVE-2012-0066, CVE-2012-0067, CVE-2012-4285,
CVE-2012-4289, CVE-2012-4290, CVE-2012-4291)

This update also fixes the following bugs :

  - When Wireshark starts with the X11 protocol being
    tunneled through an SSH connection, it automatically
    prepares its capture filter to omit the SSH packets. If
    the SSH connection was to a link-local IPv6 address
    including an interface name (for example ssh -X
    [ipv6addr]%eth0), Wireshark parsed this address
    erroneously, constructed an incorrect capture filter and
    refused to capture packets. The 'Invalid capture filter'
    message was displayed. With this update, parsing of
    link-local IPv6 addresses is fixed and Wireshark
    correctly prepares a capture filter to omit SSH packets
    over a link-local IPv6 connection.

  - Previously, Wireshark's column editing dialog malformed
    column names when they were selected. With this update,
    the dialog is fixed and no longer breaks column names.

  - Previously, TShark, the console packet analyzer, did not
    properly analyze the exit code of Dumpcap, Wireshark's
    packet capturing back end. As a result, TShark returned
    exit code 0 when Dumpcap failed to parse its
    command-line arguments. In this update, TShark correctly
    propagates the Dumpcap exit code and returns a non-zero
    exit code when Dumpcap fails.

  - Previously, the TShark '-s' (snapshot length) option
    worked only for a value greater than 68 bytes. If a
    lower value was specified, TShark captured just 68 bytes
    of incoming packets. With this update, the '-s' option
    is fixed and sizes lower than 68 bytes work as expected.

This update also adds the following enhancement :

  - In this update, support for the 'NetDump' protocol was
    added.

All running instances of Wireshark must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=1575
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b497c1fe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected wireshark, wireshark-debuginfo and / or
wireshark-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"wireshark-1.0.15-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-debuginfo-1.0.15-5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"wireshark-gnome-1.0.15-5.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
