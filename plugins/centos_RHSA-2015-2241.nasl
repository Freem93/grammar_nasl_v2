#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2241 and 
# CentOS Errata and Security Advisory 2015:2241 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87146);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_osvdb_id(120393, 120394, 120395);
  script_xref(name:"RHSA", value:"2015:2241");

  script_name(english:"CentOS 7 : chrony (CESA-2015:2241)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated chrony packages that fix three security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The chrony suite, chronyd and chronyc, is an advanced implementation
of the Network Time Protocol (NTP), specially designed to support
systems with intermittent connections. It can synchronize the system
clock with NTP servers, hardware reference clocks, and manual input.
It can also operate as an NTPv4 (RFC 5905) server or peer to provide a
time service to other computers in the network.

An out-of-bounds write flaw was found in the way chrony stored certain
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

These issues were discovered by Miroslav Lichvar of Red Hat.

The chrony packages have been upgraded to upstream version 2.1.1,
which provides a number of bug fixes and enhancements over the
previous version. Notable enhancements include :

* Updated to NTP version 4 (RFC 5905)

* Added pool directive to specify pool of NTP servers

* Added leapsecmode directive to select how to correct clock for leap
second

* Added smoothtime directive to smooth served time and enable leap
smear

* Added asynchronous name resolving with POSIX threads

* Ready for year 2036 (next NTP era)

* Improved clock control

* Networking code reworked to open separate client sockets for each
NTP server

(BZ#1117882)

This update also fixes the following bug :

* The chronyd service previously assumed that network interfaces
specified with the 'bindaddress' directive were ready when the service
was started. This could cause chronyd to fail to bind an NTP server
socket to the interface if the interface was not ready. With this
update, chronyd uses the IP_FREEBIND socket option, enabling it to
bind to an interface later, not only when the service starts.
(BZ#1169353)

In addition, this update adds the following enhancement :

* The chronyd service now supports four modes of handling leap
seconds, configured using the 'leapsecmode' option. The clock can be
either stepped by the kernel (the default 'system' mode), stepped by
chronyd ('step' mode), slowly adjusted by slewing ('slew' mode), or
the leap second can be ignored and corrected later in normal operation
('ignore' mode). If you select slewing, the correction will always
start at 00:00:00 UTC and will be applied at a rate specified in the
'maxslewrate' option. (BZ#1206504)

All chrony users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f48643ce"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chrony package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:chrony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"chrony-2.1.1-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
