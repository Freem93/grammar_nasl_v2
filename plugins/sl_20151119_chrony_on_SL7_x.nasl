#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87551);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");

  script_name(english:"Scientific Linux Security Update : chrony on SL7.x x86_64");
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
"An out-of-bounds write flaw was found in the way chrony stored certain
addresses when configuring NTP or cmdmon access. An attacker that has
the command key and is allowed to access cmdmon (only localhost is
allowed by default) could use this flaw to crash chronyd or, possibly,
execute arbitrary code with the privileges of the chronyd process.
(CVE-2015-1821)

An uninitialized pointer use flaw was found when allocating memory to
save unacknowledged replies to authenticated command requests. An
attacker that has the command key and is allowed to access cmdmon
(only localhost is allowed by default) could use this flaw to crash
chronyd or, possibly, execute arbitrary code with the privileges of
the chronyd process. (CVE-2015-1822)

A denial of service flaw was found in the way chrony hosts that were
peering with each other authenticated themselves before updating their
internal state variables. An attacker could send packets to one peer
host, which could cascade to other peers, and stop the synchronization
process among the reached peers. (CVE-2015-1853)

The chrony packages have been upgraded to upstream version 2.1.1,
which provides a number of bug fixes and enhancements over the
previous version. Notable enhancements include :

  - Updated to NTP version 4 (RFC 5905)

  - Added pool directive to specify pool of NTP servers

  - Added leapsecmode directive to select how to correct
    clock for leap second

  - Added smoothtime directive to smooth served time and
    enable leap smear

  - Added asynchronous name resolving with POSIX threads

  - Ready for year 2036 (next NTP era)

  - Improved clock control

  - Networking code reworked to open separate client sockets
    for each NTP server

This update also fixes the following bug :

  - The chronyd service previously assumed that network
    interfaces specified with the 'bindaddress' directive
    were ready when the service was started. This could
    cause chronyd to fail to bind an NTP server socket to
    the interface if the interface was not ready. With this
    update, chronyd uses the IP_FREEBIND socket option,
    enabling it to bind to an interface later, not only when
    the service starts.

In addition, this update adds the following enhancement :

  - The chronyd service now supports four modes of handling
    leap seconds, configured using the 'leapsecmode' option.
    The clock can be either stepped by the kernel (the
    default 'system' mode), stepped by chronyd ('step'
    mode), slowly adjusted by slewing ('slew' mode), or the
    leap second can be ignored and corrected later in normal
    operation ('ignore' mode). If you select slewing, the
    correction will always start at 00:00:00 UTC and will be
    applied at a rate specified in the 'maxslewrate' option."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=5577
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe875d88"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chrony and / or chrony-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"chrony-2.1.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"chrony-debuginfo-2.1.1-1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
