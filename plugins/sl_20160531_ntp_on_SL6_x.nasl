#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(91644);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id("CVE-2015-7979", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2518");

  script_name(english:"Scientific Linux Security Update : ntp on SL6.x, SL7.x i386/x86_64");
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
"Security Fix(es) :

  - It was found that when NTP was configured in broadcast
    mode, a remote attacker could broadcast packets with bad
    authentication to all clients. The clients, upon
    receiving the malformed packets, would break the
    association with the broadcast server, causing them to
    become out of sync over a longer period of time.
    (CVE-2015-7979)

  - A denial of service flaw was found in the way NTP
    handled preemptable client associations. A remote
    attacker could send several crypto NAK packets to a
    victim client, each with a spoofed source address of an
    existing associated peer, preventing that client from
    synchronizing its time. (CVE-2016-1547)

  - It was found that an ntpd client could be forced to
    change from basic client/server mode to the interleaved
    symmetric mode. A remote attacker could use a spoofed
    packet that, when processed by an ntpd client, would
    cause that client to reject all future legitimate server
    responses, effectively disabling time synchronization on
    that client. (CVE-2016-1548)

  - A flaw was found in the way NTP's libntp performed
    message authentication. An attacker able to observe the
    timing of the comparison function used in packet
    authentication could potentially use this flaw to
    recover the message digest. (CVE-2016-1550)

  - An out-of-bounds access flaw was found in the way ntpd
    processed certain packets. An authenticated attacker
    could use a crafted packet to create a peer association
    with hmode of 7 and larger, which could potentially
    (although highly unlikely) cause ntpd to crash.
    (CVE-2016-2518)

The CVE-2016-1548 issue was discovered by Miroslav Lichvar (Red Hat)."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=5337
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7be3f1b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"ntp-4.2.6p5-10.el6.1")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-debuginfo-4.2.6p5-10.el6.1")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-doc-4.2.6p5-10.el6.1")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-perl-4.2.6p5-10.el6.1")) flag++;
if (rpm_check(release:"SL6", reference:"ntpdate-4.2.6p5-10.el6.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-4.2.6p5-22.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-22.el7_2.2")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-doc-4.2.6p5-22.el7_2.2")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-perl-4.2.6p5-22.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-22.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sntp-4.2.6p5-22.el7_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
