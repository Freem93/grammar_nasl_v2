#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2101. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86968);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-4616", "CVE-2014-4650", "CVE-2014-7185");
  script_osvdb_id(101381, 101382, 101383, 101384, 101385, 101386, 106016, 108354, 108369, 112028);
  script_xref(name:"RHSA", value:"2015:2101");

  script_name(english:"RHEL 7 : python (RHSA-2015:2101)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Python is an interpreted, interactive, object-oriented programming
language often compared to Tcl, Perl, Scheme, or Java. Python includes
modules, classes, exceptions, very high level dynamic data types and
dynamic typing. Python supports interfaces to many system calls and
libraries, as well as to various windowing systems (X11, Motif, Tk,
Mac and MFC).

It was discovered that the Python xmlrpclib module did not restrict
the size of gzip-compressed HTTP responses. A malicious XMLRPC server
could cause an XMLRPC client using xmlrpclib to consume an excessive
amount of memory. (CVE-2013-1753)

It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict the sizes of server responses. A malicious server could cause
a client using one of the affected modules to consume an excessive
amount of memory. (CVE-2013-1752)

It was discovered that the CGIHTTPServer module incorrectly handled
URL encoded paths. A remote attacker could use this flaw to execute
scripts outside of the cgi-bin directory, or disclose the source code
of the scripts in the cgi-bin directory. (CVE-2014-4650)

An integer overflow flaw was found in the way the buffer() function
handled its offset and size arguments. An attacker able to control
these arguments could use this flaw to disclose portions of the
application memory or cause it to crash. (CVE-2014-7185)

A flaw was found in the way the json module handled negative index
arguments passed to certain functions (such as raw_decode()). An
attacker able to control the index value passed to one of the affected
functions could possibly use this flaw to disclose portions of the
application memory. (CVE-2014-4616)

The Python standard library HTTP client modules (such as httplib or
urllib) did not perform verification of TLS/SSL certificates when
connecting to HTTPS servers. A man-in-the-middle attacker could use
this flaw to hijack connections and eavesdrop or modify transferred
data. (CVE-2014-9365)

Note: The Python standard library was updated to make it possible to
enable certificate verification by default. However, for backwards
compatibility, verification remains disabled by default. Future
updates may change this default. Refer to the Knowledgebase article
2039753 linked to in the References section for further details about
this change. (BZ#1219108)

This update also fixes the following bugs :

* Subprocesses used with the Eventlet library or regular threads
previously tried to close epoll file descriptors twice, which led to
an 'Invalid argument' error. Subprocesses have been fixed to close the
file descriptors only once. (BZ#1103452)

* When importing the readline module from a Python script, Python no
longer produces erroneous random characters on stdout. (BZ#1189301)

* The cProfile utility has been fixed to print all values that the
'-s' option supports when this option is used without a correct value.
(BZ#1237107)

* The load_cert_chain() function now accepts 'None' as a keyfile
argument. (BZ#1250611)

In addition, this update adds the following enhancements :

* Security enhancements as described in PEP 466 have been backported
to the Python standard library, for example, new features of the ssl
module: Server Name Indication (SNI) support, support for new TLSv1.x
protocols, new hash algorithms in the hashlib module, and many more.
(BZ#1111461)

* Support for the ssl.PROTOCOL_TLSv1_2 protocol has been added to the
ssl library. (BZ#1192015)

* The ssl.SSLSocket.version() method is now available to access
information about the version of the SSL protocol used in a
connection. (BZ#1259421)

All python users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1753.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4616.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4650.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2039753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0466/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2101.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2101";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-debug-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-debug-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-debuginfo-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-devel-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-devel-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-libs-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-test-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-test-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-tools-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-tools-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tkinter-2.7.5-34.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tkinter-2.7.5-34.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-debuginfo / python-devel / etc");
  }
}
