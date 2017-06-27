#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1278 and 
# CentOS Errata and Security Advisory 2009:1278 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43780);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/06/28 23:49:39 $");

  script_cve_id("CVE-2007-2348");
  script_xref(name:"RHSA", value:"2009:1278");

  script_name(english:"CentOS 5 : lftp (CESA-2009:1278)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated lftp package that fixes one security issue and various bugs
is now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

LFTP is a sophisticated file transfer program for the FTP and HTTP
protocols. Like bash, it has job control and uses the readline library
for input. It has bookmarks, built-in mirroring, and can transfer
several files in parallel. It is designed with reliability in mind.

It was discovered that lftp did not properly escape shell
metacharacters when generating shell scripts using the 'mirror
--script' command. A mirroring script generated to download files from
a malicious FTP server could allow an attacker controlling the FTP
server to run an arbitrary command as the user running lftp.
(CVE-2007-2348)

This update also fixes the following bugs :

* when using the 'mirror' or 'get' commands with the '-c' option, lftp
did not check for some specific conditions that could result in the
program becoming unresponsive, hanging and the command not completing.
For example, when waiting for a directory listing, if lftp received a
'226' message, denoting an empty directory, it previously ignored the
message and kept waiting. With this update, these conditions are
properly checked for and lftp no longer hangs when '-c' is used with
'mirror' or 'get'. (BZ#422881)

* when using the 'put', 'mput' or 'reput' commands over a Secure FTP
(SFTP) connection, specifying the '-c' option sometimes resulted in
corrupted files of incorrect size. With this update, using these
commands over SFTP with the '-c' option works as expected, and
transferred files are no longer corrupted in the transfer process.
(BZ#434294)

* previously, LFTP linked to the OpenSSL library. OpenSSL's license
is, however, incompatible with LFTP's GNU GPL license and LFTP does
not include an exception allowing OpenSSL linking. With this update,
LFTP links to the GnuTLS (GNU Transport Layer Security) library, which
is released under the GNU LGPL license. Like OpenSSL, GnuTLS
implements the SSL and TLS protocols, so functionality has not
changed. (BZ#458777)

* running 'help mirror' from within lftp only presented a sub-set of
the available options compared to the full list presented in the man
page. With this update, running 'help mirror' in lftp presents the
same list of mirror options as is available in the Commands section of
the lftp man page. (BZ#461922)

* LFTP imports gnu-lib from upstream. Subsequent to gnu-lib switching
from GNU GPLv2 to GNU GPLv3, the LFTP license was internally
inconsistent, with LFTP licensed as GNU GPLv2 but portions of the
package apparently licensed as GNU GPLv3 because of changes made by
the gnu-lib import. With this update, LFTP itself switches to GNU
GPLv3, resolving the inconsistency. (BZ#468858)

* when the 'ls' command was used within lftp to present a directory
listing on a remote system connected to via HTTP, file names
containing spaces were presented incorrectly. This update corrects
this behavior. (BZ#504591)

* the default alias 'edit' did not define a default editor. If EDITOR
was not set in advance by the system, lftp attempted to execute
'~/.lftp/edit.tmp.$$' (which failed because the file is not set to
executable). The edit alias also did not support tab-completion of
file names and incorrectly interpreted file names containing spaces.
The updated package defines a default editor (vi) in the absence of a
system-defined EDITOR. The edit alias now also supports tab-completion
and handles file names containing spaces correctly for both
downloading and uploading. (BZ#504594)

Note: This update upgrades LFTP from version 3.7.3 to upstream version
3.7.11, which incorporates a number of further bug fixes to those
noted above. For details regarding these fixes, refer to the
'/usr/share/doc/lftp-3.7.11/NEWS' file after installing this update.
(BZ#308721)

All LFTP users are advised to upgrade to this updated package, which
resolves these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016139.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc38d6cb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a938c3c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lftp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lftp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"lftp-3.7.11-4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
