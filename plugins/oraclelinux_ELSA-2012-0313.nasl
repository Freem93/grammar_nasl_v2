#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0313 and 
# Oracle Linux Security Advisory ELSA-2012-0313 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68484);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2010-0926");
  script_bugtraq_id(37992, 38111, 38326, 43212, 46597, 48899, 48901, 49939);
  script_osvdb_id(62145);
  script_xref(name:"RHSA", value:"2012:0313");

  script_name(english:"Oracle Linux 5 : samba (ELSA-2012-0313)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0313 :

Updated samba packages that fix one security issue, one bug, and add
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
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002664.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"libsmbclient-3.0.33-3.37.el5")) flag++;
if (rpm_check(release:"EL5", reference:"libsmbclient-devel-3.0.33-3.37.el5")) flag++;
if (rpm_check(release:"EL5", reference:"samba-3.0.33-3.37.el5")) flag++;
if (rpm_check(release:"EL5", reference:"samba-client-3.0.33-3.37.el5")) flag++;
if (rpm_check(release:"EL5", reference:"samba-common-3.0.33-3.37.el5")) flag++;
if (rpm_check(release:"EL5", reference:"samba-swat-3.0.33-3.37.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
}
