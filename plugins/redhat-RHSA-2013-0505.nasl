#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0505. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64756);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-5643");
  script_osvdb_id(88492);
  script_xref(name:"RHSA", value:"2013:0505");

  script_name(english:"RHEL 6 : squid (RHSA-2013:0505)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Squid is a high-performance proxy caching server for web clients that
supports FTP, Gopher, and HTTP data objects.

A denial of service flaw was found in the way the Squid Cache Manager
processed certain requests. A remote attacker who is able to access
the Cache Manager CGI could use this flaw to cause Squid to consume an
excessive amount of memory. (CVE-2012-5643)

This update also fixes the following bugs :

* Due to a bug in the ConnStateData::noteMoreBodySpaceAvailable()
function, child processes of Squid terminated upon encountering a
failed assertion. An upstream patch has been provided and Squid child
processes no longer terminate. (BZ#805879)

* Due to an upstream patch, which renamed the HTTP header controlling
persistent connections from 'Proxy-Connection' to 'Connection', the
NTLM pass-through authentication does not work, thus preventing login.
This update adds the new 'http10' option to the squid.conf file, which
can be used to enable the change in the patch. This option is set to
'off' by default. When set to 'on', the NTLM pass-through
authentication works properly, thus allowing login attempts to
succeed. (BZ#844723)

* When the IPv6 protocol was disabled and Squid tried to handle an
HTTP GET request containing an IPv6 address, the Squid child process
terminated due to signal 6. This bug has been fixed and such requests
are now handled as expected. (BZ#832484)

* The old 'stale if hit' logic did not account for cases where the
stored stale response became fresh due to a successful re-validation
with the origin server. Consequently, incorrect warning messages were
returned. Now, Squid no longer marks elements as stale in the
described scenario. (BZ#847056)

* When squid packages were installed before samba-winbind, the wbpriv
group did not include Squid. Consequently, NTLM authentication calls
failed. Now, Squid correctly adds itself into the wbpriv group if
samba-winbind is installed before Squid, thus fixing this bug.
(BZ#797571)

* In FIPS mode, Squid was using private MD5 hash functions for user
authentication and network access. As MD5 is incompatible with FIPS
mode, Squid could fail to start. This update limits the use of the
private MD5 functions to local disk file hash identifiers, thus
allowing Squid to work in FIPS mode. (BZ#833086)

* Under high system load, the squid process could terminate
unexpectedly with a segmentation fault during reboot. This update
provides better memory handling during reboot, thus fixing this bug.
(BZ#782732)

* Squid incorrectly set the timeout limit for client HTTP connections
with the value for server-side connections, which is much higher, thus
creating unnecessary delays. With this update, Squid uses a proper
value for the client timeout limit. (BZ#798090)

* Squid did not properly release allocated memory when generating
error page contents, which caused memory leaks. Consequently, the
Squid proxy server consumed a lot of memory within a short time
period. This update fixes this memory leak. (BZ#758861)

* Squid did not pass the ident value to a URL rewriter that was
configured using the 'url_rewrite_program' directive. Consequently,
the URL rewriter received the dash character ('-') as the user value
instead of the correct user name. Now, the URL rewriter receives the
correct user name in the described scenario. (BZ#797884)

* Squid, used as a transparent proxy, can only handle the HTTP
protocol. Previously, it was possible to define a URL in which the
access protocol contained the asterisk character (*) or an unknown
protocol namespace URI. Consequently, an 'Invalid URL' error message
was logged to access.log during reload. This update ensures that
'http://' is always used in transparent proxy URLs, and the error
message is no longer logged in this scenario. (BZ#720504)

All users of squid are advised to upgrade to these updated packages,
which fix these issues. After installing this update, the squid
service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5643.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faae67f0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0505.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?879a0985"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid and / or squid-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0505";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"squid-3.1.10-16.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"squid-3.1.10-16.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"squid-3.1.10-16.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"squid-debuginfo-3.1.10-16.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"squid-debuginfo-3.1.10-16.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"squid-debuginfo-3.1.10-16.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo");
  }
}
