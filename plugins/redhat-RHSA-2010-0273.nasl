#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0273. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46288);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2010-0734");
  script_bugtraq_id(38162);
  script_xref(name:"RHSA", value:"2010:0273");

  script_name(english:"RHEL 5 : curl (RHSA-2010:0273)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix one security issue, various bugs, and
add enhancements are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
DICT servers, using any of the supported protocols. cURL is designed
to work without user interaction or any kind of interactivity.

Wesley Miaw discovered that when deflate compression was used, libcurl
could call the registered write callback function with data exceeding
the documented limit. A malicious server could use this flaw to crash
an application using libcurl or, potentially, execute arbitrary code.
Note: This issue only affected applications using libcurl that rely on
the documented data size limit, and that copy the data to the
insufficiently sized buffer. (CVE-2010-0734)

This update also fixes the following bugs :

* when using curl to upload a file, if the connection was broken or
reset by the server during the transfer, curl immediately started
using 100% CPU and failed to acknowledge that the transfer had failed.
With this update, curl displays an appropriate error message and exits
when an upload fails mid-transfer due to a broken or reset connection.
(BZ#479967)

* libcurl experienced a segmentation fault when attempting to reuse a
connection after performing GSS-negotiate authentication, which in
turn caused the curl program to crash. This update fixes this bug so
that reused connections are able to be successfully established even
after GSS-negotiate authentication has been performed. (BZ#517199)

As well, this update adds the following enhancements :

* curl now supports loading Certificate Revocation Lists (CRLs) from a
Privacy Enhanced Mail (PEM) file. When curl attempts to access sites
that have had their certificate revoked in a CRL, curl refuses access
to those sites. (BZ#532069)

* the curl(1) manual page has been updated to clarify that the
'--socks4' and '--socks5' options do not work with the IPv6, FTPS, or
LDAP protocols. (BZ#473128)

* the curl utility's program help, which is accessed by running 'curl
-h', has been updated with descriptions for the '--ftp-account' and
'--ftp-alternative-to-user' options. (BZ#517084)

Users of curl should upgrade to these updated packages, which contain
backported patches to correct these issues and add these enhancements.
All running applications using libcurl must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0273.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected curl and / or curl-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:curl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0273";
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
  if (rpm_check(release:"RHEL5", reference:"curl-7.15.5-9.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"curl-devel-7.15.5-9.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-devel");
  }
}
