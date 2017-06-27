#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0313. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58067);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2010-0926");
  script_bugtraq_id(38111);
  script_osvdb_id(62145);
  script_xref(name:"RHSA", value:"2012:0313");

  script_name(english:"RHEL 5 : samba (RHSA-2012:0313)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix one security issue, one bug, and add
one enhancement are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

The default Samba server configuration enabled both the 'wide links'
and 'unix extensions' options, allowing Samba clients with write
access to a share to create symbolic links that point to any location
on the file system. Clients connecting with CIFS UNIX extensions
disabled could have such links resolved on the server, allowing them
to access and possibly overwrite files outside of the share. With this
update, 'wide links' is set to 'no' by default. In addition, the
update ensures 'wide links' is disabled for shares that have 'unix
extensions' enabled. (CVE-2010-0926)

Warning: This update may cause files and directories that are only
linked to Samba shares using symbolic links to become inaccessible to
Samba clients. In deployments where support for CIFS UNIX extensions
is not needed (such as when files are exported to Microsoft Windows
clients), administrators may prefer to set the 'unix extensions'
option to 'no' to allow the use of symbolic links to access files out
of the shared directories. All existing symbolic links in a share
should be reviewed before re-enabling 'wide links'.

These updated samba packages also fix the following bug :

* The smbclient tool sometimes failed to return the proper exit status
code. Consequently, using smbclient in a script caused some scripts to
fail. With this update, an upstream patch has been applied and
smbclient now returns the correct exit status. (BZ#768908)

In addition, these updated samba packages provide the following
enhancement :

* With this update, support for Windows Server 2008 R2 domains has
been added. (BZ#736124)

Users are advised to upgrade to these updated samba packages, which
correct these issues and add this enhancement. After installing this
update, the smb service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0926.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0313.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:0313";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", reference:"libsmbclient-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libsmbclient-devel-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-client-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-client-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-client-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"samba-common-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"samba-debuginfo-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-swat-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-swat-3.0.33-3.37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-swat-3.0.33-3.37.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
  }
}
