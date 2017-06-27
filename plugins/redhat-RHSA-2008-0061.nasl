#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0061. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32419);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:16:32 $");

  script_cve_id("CVE-2007-5495", "CVE-2007-5496");
  script_osvdb_id(45671, 45672);
  script_xref(name:"RHSA", value:"2008:0061");

  script_name(english:"RHEL 5 : setroubleshoot (RHSA-2008:0061)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated setroubleshoot packages that fix two security issues and
several bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The setroubleshoot packages provide tools to help diagnose SELinux
problems. When AVC messages occur, an alert is generated that gives
information about the problem, and how to create a resolution.

A flaw was found in the way sealert wrote diagnostic messages to a
temporary file. A local unprivileged user could perform a symbolic
link attack, and cause arbitrary files, writable by other users, to be
overwritten when a victim runs sealert. (CVE-2007-5495)

A flaw was found in the way sealert displayed records from the
setroubleshoot database as unescaped HTML. An local unprivileged
attacker could cause AVC denial events with carefully crafted process
or file names, injecting arbitrary HTML tags into the logs, which
could be used as a scripting attack, or to confuse the user running
sealert. (CVE-2007-5496)

Additionally, the following bugs have been fixed in these update
packages :

* in certain situations, the sealert process used excessive CPU. These
alerts are now capped at a maximum of 30, D-Bus is used instead of
polling, threads causing excessive wake-up have been removed, and more
robust exception-handling has been added.

* different combinations of the sealert '-a', '-l', '-H', and '-v'
options did not work as documented.

* the SETroubleShoot browser did not allow multiple entries to be
deleted.

* the SETroubleShoot browser did not display statements that displayed
whether SELinux was using Enforcing or Permissive mode, particularly
when warning about SELinux preventions.

* in certain cases, the SETroubleShoot browser gave incorrect
instructions regarding paths, and would not display the full paths to
files.

* adding an email recipient to the recipients option from the
/etc/setroubleshoot/setroubleshoot.cfg file and then generating an
SELinux denial caused a traceback error. The recipients option has
been removed; email addresses are now managed through the
SETroubleShoot browser by navigating to File -> Edit Email Alert List,
or by editing the /var/lib/setroubleshoot/email_alert_recipients file.

* the setroubleshoot browser incorrectly displayed a period between
the httpd_sys_content_t context and the directory path.

* on the PowerPC architecture, The get_credentials() function in
access_control.py would generate an exception when it called the
socket.getsockopt() function.

* The code which handles path information has been completely
rewritten so that assumptions on path information which were
misleading are no longer made. If the path information is not present,
it will be presented as '<Unknown>'.

* setroubleshoot had problems with non-English locales under certain
circumstances, possibly causing a python traceback, an sealert window
pop-up containing an error, a 'RuntimeError: maximum recursion depth
exceeded' error after a traceback, or a 'UnicodeEncodeError' after a
traceback.

* sealert ran even when SELinux was disabled, causing 'attempt to open
server connection failed' errors. Sealert now checks whether SELinux
is enabled or disabled.

* the database setroubleshoot maintains was world-readable. The
setroubleshoot database is now mode 600, and is owned by the root user
and group.

* setroubleshoot did not validate requests to set AVC filtering
options for users. In these updated packages, checks ensure that
requests originate from the filter owner.

* the previous setroubleshoot packages required a number of GNOME
packages and libraries. setroubleshoot has therefore been split into 2
packages: setroubleshoot and setroubleshoot-server.

* a bug in decoding the audit field caused an 'Input is not proper
UTF-8, indicate encoding!' error message. The decoding code has been
rewritten.

* a file name mismatch in the setroubleshoot init script would cause a
failure to shut down.

Users of setroubleshoot are advised to upgrade to these updated
packages, which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0061.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected setroubleshoot, setroubleshoot-plugins and / or
setroubleshoot-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(59, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0061";
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
  if (rpm_check(release:"RHEL5", reference:"setroubleshoot-2.0.5-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"setroubleshoot-plugins-2.0.4-2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"setroubleshoot-server-2.0.5-3.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "setroubleshoot / setroubleshoot-plugins / setroubleshoot-server");
  }
}
