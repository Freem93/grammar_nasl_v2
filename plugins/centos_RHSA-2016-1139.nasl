#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1139 and 
# CentOS Errata and Security Advisory 2016:1139 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91392);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_osvdb_id(137402, 137403, 137404, 137405, 138132, 138133, 138134);
  script_xref(name:"RHSA", value:"2016:1139");

  script_name(english:"CentOS 7 : squid (CESA-2016:1139)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for squid is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Squid is a high-performance proxy caching server for web clients,
supporting FTP, Gopher, and HTTP data objects.

Security Fix(es) :

* A buffer overflow flaw was found in the way the Squid cachemgr.cgi
utility processed remotely relayed Squid input. When the CGI interface
utility is used, a remote attacker could possibly use this flaw to
execute arbitrary code. (CVE-2016-4051)

* Buffer overflow and input validation flaws were found in the way
Squid processed ESI responses. If Squid was used as a reverse proxy,
or for TLS/HTTPS interception, a remote attacker able to control ESI
components on an HTTP server could use these flaws to crash Squid,
disclose parts of the stack memory, or possibly execute arbitrary code
as the user running Squid. (CVE-2016-4052, CVE-2016-4053,
CVE-2016-4054)

* An input validation flaw was found in the way Squid handled
intercepted HTTP Request messages. An attacker could use this flaw to
bypass the protection against issues related to CVE-2009-0801, and
perform cache poisoning attacks on Squid. (CVE-2016-4553)

* An input validation flaw was found in Squid's
mime_get_header_field() function, which is used to search for headers
within HTTP requests. An attacker could send an HTTP request from the
client side with specially crafted header Host header that bypasses
same-origin security protections, causing Squid operating as
interception or reverse-proxy to contact the wrong origin server. It
could also be used for cache poisoning for client not following RFC
7230. (CVE-2016-4554)

* A NULL pointer dereference flaw was found in the way Squid processes
ESI responses. If Squid was used as a reverse proxy or for TLS/HTTPS
interception, a malicious server could use this flaw to crash the
Squid worker process. (CVE-2016-4555)

* An incorrect reference counting flaw was found in the way Squid
processes ESI responses. If Squid is configured as reverse-proxy, for
TLS/HTTPS interception, an attacker controlling a server accessed by
Squid, could crash the squid worker, causing a Denial of Service
attack. (CVE-2016-4556)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021900.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid-sysvinit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"squid-3.3.8-26.el7_2.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"squid-sysvinit-3.3.8-26.el7_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
