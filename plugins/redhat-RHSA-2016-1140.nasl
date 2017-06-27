#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1140. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91383);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/10 20:34:13 $");

  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_osvdb_id(137402, 137403, 137404, 137405, 138132, 138133, 138134);
  script_xref(name:"RHSA", value:"2016:1140");

  script_name(english:"RHEL 6 : squid34 (RHSA-2016:1140)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for squid34 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The 'squid34' packages provide version 3.4 of Squid, a
high-performance proxy caching server for web clients, supporting FTP,
Gopher, and HTTP data objects. Note that apart from 'squid34', this
version of Red Hat Enterprise Linux also includes the 'squid' packages
which provide Squid version 3.1.

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
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2016_5.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2016_6.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2016_7.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2016_8.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2016_9.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1140.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid34 and / or squid34-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1140";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"squid34-3.4.14-9.el6_8.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"squid34-3.4.14-9.el6_8.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"squid34-3.4.14-9.el6_8.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"squid34-debuginfo-3.4.14-9.el6_8.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"squid34-debuginfo-3.4.14-9.el6_8.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"squid34-debuginfo-3.4.14-9.el6_8.3")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid34 / squid34-debuginfo");
  }
}
