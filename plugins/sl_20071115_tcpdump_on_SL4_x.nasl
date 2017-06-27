#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60310);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-1218", "CVE-2007-3798");

  script_name(english:"Scientific Linux Security Update : tcpdump on SL4.x i386/x86_64");
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
"Moritz Jodeit discovered a denial of service bug in the tcpdump IEEE
802.11 processing code. An attacker could inject a carefully crafted
frame onto the IEEE 802.11 network that could crash a running tcpdump
session if a certain link type was explicitly specified.
(CVE-2007-1218)

An integer overflow flaw was found in tcpdump's BGP processing code.
An attacker could execute arbitrary code with the privilege of the
pcap user by injecting a crafted frame onto the network.
(CVE-2007-3798)

In addition, the following bugs have been addressed :

  - if called with -C and -W switches, tcpdump would create
    the first savefile with the privileges of the user that
    executed tcpdump (usually root), rather than with ones
    of the pcap user. This could result in the inability to
    save the complete traffic log file properly without the
    immediate notice of the user running tcpdump.

  - the arpwatch service initialization script would exit
    prematurely, returning a successful exit status
    incorrectly and preventing the status command from
    running in case networking is not available."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=4200
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5626042"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected arpwatch, libpcap and / or tcpdump packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
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
if (rpm_check(release:"SL4", reference:"arpwatch-2.1a13-12.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpcap-0.8.3-12.el4")) flag++;
if (rpm_check(release:"SL4", reference:"tcpdump-3.8.2-12.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
