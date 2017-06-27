#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0018. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24316);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/29 15:35:20 $");

  script_cve_id("CVE-2005-4348", "CVE-2006-5867");
  script_bugtraq_id(15987, 21903);
  script_osvdb_id(21906, 31580);
  script_xref(name:"RHSA", value:"2007:0018");

  script_name(english:"RHEL 2.1 / 3 / 4 : fetchmail (RHSA-2007:0018)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated fetchmail packages that fix two security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Fetchmail is a remote mail retrieval and forwarding utility.

A denial of service flaw was found when Fetchmail was run in multidrop
mode. A malicious mail server could send a message without headers
which would cause Fetchmail to crash (CVE-2005-4348). This issue did
not affect the version of Fetchmail shipped with Red Hat Enterprise
Linux 2.1 or 3.

A flaw was found in the way Fetchmail used TLS encryption to connect
to remote hosts. Fetchmail provided no way to enforce the use of TLS
encryption and would not authenticate POP3 protocol connections
properly (CVE-2006-5867). This update corrects this issue by enforcing
TLS encryption when the 'sslproto' configuration directive is set to
'tls1'.

Users of Fetchmail should update to these packages, which contain
backported patches to correct these issues.

Note: This update may break configurations which assumed that
Fetchmail would use plain-text authentication if TLS encryption is not
supported by the POP3 server even if the 'sslproto' directive is set
to 'tls1'. If you are using a custom configuration that depended on
this behavior you will need to modify your configuration appropriately
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-4348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-5867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://fetchmail.berlios.de/fetchmail-SA-2005-03.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://fetchmail.berlios.de/fetchmail-SA-2006-03.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0018.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fetchmail and / or fetchmailconf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fetchmailconf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0018";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"fetchmail-5.9.0-21.7.3.el2.1.4")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"fetchmailconf-5.9.0-21.7.3.el2.1.4")) flag++;

  if (rpm_check(release:"RHEL3", reference:"fetchmail-6.2.0-3.el3.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"fetchmail-6.2.5-6.el4.5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fetchmail / fetchmailconf");
  }
}
