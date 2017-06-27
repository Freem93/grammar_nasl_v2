#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:061. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16384);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211", "CVE-2005-0241");
  script_bugtraq_id(12276);
  script_osvdb_id(12816, 12886, 12887, 13054, 13114, 13319, 13345, 13346, 13732);
  script_xref(name:"RHSA", value:"2005:061");

  script_name(english:"RHEL 2.1 / 3 : squid (RHSA-2005:061)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Squid package that fixes several security issues is now
available.

Squid is a full-featured Web proxy cache.

A buffer overflow flaw was found in the Gopher relay parser. This bug
could allow a remote Gopher server to crash the Squid proxy that reads
data from it. Although Gopher servers are now quite rare, a malicious
web page (for example) could redirect or contain a frame pointing to
an attacker's malicious gopher server. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0094
to this issue.

An integer overflow flaw was found in the WCCP message parser. It is
possible to crash the Squid server if an attacker is able to send a
malformed WCCP message with a spoofed source address matching Squid's
'home router'. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0095 to this issue.

A memory leak was found in the NTLM fakeauth_auth helper. It is
possible that an attacker could place the Squid server under high
load, causing the NTML fakeauth_auth helper to consume a large amount
of memory, resulting in a denial of service. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0096 to this issue.

A NULL pointer de-reference bug was found in the NTLM fakeauth_auth
helper. It is possible for an attacker to send a malformed NTLM type 3
message, causing the Squid server to crash. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-0097 to this issue.

A username validation bug was found in squid_ldap_auth. It is possible
for a username to be padded with spaces, which could allow a user to
bypass explicit access control rules or confuse accounting. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0173 to this issue.

The way Squid handles HTTP responses was found to need strengthening.
It is possible that a malicious web server could send a series of HTTP
responses in such a way that the Squid cache could be poisoned,
presenting users with incorrect webpages. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the names
CVE-2005-0174 and CVE-2005-0175 to these issues.

A bug was found in the way Squid handled oversized HTTP response
headers. It is possible that a malicious web server could send a
specially crafted HTTP header which could cause the Squid cache to be
poisoned, presenting users with incorrect webpages. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0241 to this issue.

A buffer overflow bug was found in the WCCP message parser. It is
possible that an attacker could send a malformed WCCP message which
could crash the Squid server or execute arbitrary code. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0211 to this issue.

Users of Squid should upgrade to this updated package, which contains
backported patches, and is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0173.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0211.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0241.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2005_1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2005_2.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2005_3.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Versions/v2/2.5/bugs/#"
  );
  # http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE7-ldap_spaces
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96864d1c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-061.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:061";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"squid-2.4.STABLE7-1.21as.4")) flag++;

  if (rpm_check(release:"RHEL3", reference:"squid-2.5.STABLE3-6.3E.7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
  }
}
