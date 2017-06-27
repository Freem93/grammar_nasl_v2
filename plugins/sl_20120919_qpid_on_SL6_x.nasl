#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62218);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/09/29 23:06:12 $");

  script_cve_id("CVE-2012-2145");

  script_name(english:"Scientific Linux Security Update : qpid on SL6.x i386/x86_64");
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
"Apache Qpid is a reliable, cross-platform, asynchronous messaging
system that supports the Advanced Message Queuing Protocol (AMQP) in
several common programming languages.

It was discovered that the Qpid daemon (qpidd) did not allow the
number of connections from clients to be restricted. A malicious
client could use this flaw to open an excessive amount of connections,
preventing other legitimate clients from establishing a connection to
qpidd. (CVE-2012-2145)

To address CVE-2012-2145, new qpidd configuration options were
introduced: max-negotiate-time defines the time during which initial
protocol negotiation must succeed, connection-limit-per-user and
connection-limit-per-ip can be used to limit the number of connections
per user and client host IP. Refer to the qpidd manual page for
additional details.

In addition, the qpid-cpp, qpid-qmf, qpid-tools, and python-qpid
packages have been upgraded to upstream version 0.14, which provides a
number of bug fixes and enhancements over the previous version.

All users of qpid are advised to upgrade to these updated packages,
which fix these issues and add these enhancements.

For dependency resolution saslwrapper, saslwrapper-devel,
python-saslwrapper, and ruby-saslwrapper have been added to this
update"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=3414
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c534bd9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/21");
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
if (rpm_check(release:"SL6", reference:"python-qpid-0.14-11.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"python-qpid-qmf-0.14-14.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-client-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-client-ssl-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-server-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-cpp-server-ssl-0.14-22.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-qmf-0.14-14.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"qpid-tools-0.14-6.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-qpid-qmf-0.14-14.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
