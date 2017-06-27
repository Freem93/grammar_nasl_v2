#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1462 and 
# CentOS Errata and Security Advisory 2015:1462 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85027);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/28 16:58:13 $");

  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_bugtraq_id(71106, 71107);
  script_osvdb_id(112034, 112155);
  script_xref(name:"RHSA", value:"2015:1462");

  script_name(english:"CentOS 6 : ipa (CESA-2015:1462)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipa packages that fix two security issues and several bugs are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Two cross-site scripting (XSS) flaws were found in jQuery, which
impacted the Identity Management web administrative interface, and
could allow an authenticated user to inject arbitrary HTML or web
script into the interface. (CVE-2010-5312, CVE-2012-6662)

Note: The IdM version provided by this update no longer uses jQuery.

Bug fixes :

* The ipa-server-install, ipa-replica-install, and ipa-client-install
utilities are not supported on machines running in FIPS-140 mode.
Previously, IdM did not warn users about this. Now, IdM does not allow
running the utilities in FIPS-140 mode, and displays an explanatory
message. (BZ#1131571)

* If an Active Directory (AD) server was specified or discovered
automatically when running the ipa-client-install utility, the utility
produced a traceback instead of informing the user that an IdM server
is expected in this situation. Now, ipa-client-install detects the AD
server and fails with an explanatory message. (BZ#1132261)

* When IdM servers were configured to require the TLS protocol version
1.1 (TLSv1.1) or later in the httpd server, the ipa utility failed.
With this update, running ipa works as expected with TLSv1.1 or later.
(BZ#1154687)

* In certain high-load environments, the Kerberos authentication step
of the IdM client installer can fail. Previously, the entire client
installation failed in this situation. This update modifies
ipa-client-install to prefer the TCP protocol over the UDP protocol
and to retry the authentication attempt in case of failure.
(BZ#1161722)

* If ipa-client-install updated or created the /etc/nsswitch.conf
file, the sudo utility could terminate unexpectedly with a
segmentation fault. Now, ipa-client-install puts a new line character
at the end of nsswitch.conf if it modifies the last line of the file,
fixing this bug. (BZ#1185207)

* The ipa-client-automount utility failed with the
'UNWILLING_TO_PERFORM' LDAP error when the nsslapd-minssf Red Hat
Directory Server configuration parameter was set to '1'. This update
modifies ipa-client-automount to use encrypted connection for LDAP
searches by default, and the utility now finishes successfully even
with nsslapd-minssf specified. (BZ#1191040)

* If installing an IdM server failed after the Certificate Authority
(CA) installation, the 'ipa-server-install --uninstall' command did
not perform a proper cleanup. After the user issued
'ipa-server-install --uninstall' and then attempted to install the
server again, the installation failed. Now, 'ipa-server-install
--uninstall' removes the CA-related files in the described situation,
and ipa-server-install no longer fails with the mentioned error
message. (BZ#1198160)

* Running ipa-client-install added the 'sss' entry to the sudoers line
in nsswitch.conf even if 'sss' was already configured and the entry
was present in the file. Duplicate 'sss' then caused sudo to become
unresponsive. Now, ipa-client-install no longer adds 'sss' if it is
already present in nsswitch.conf. (BZ#1198339)

* After running ipa-client-install, it was not possible to log in
using SSH under certain circumstances. Now, ipa-client-install no
longer corrupts the sshd_config file, and the sshd service can start
as expected, and logging in using SSH works in the described
situation. (BZ#1201454)

* An incorrect definition of the dc attribute in the
/usr/share/ipa/05rfc2247.ldif file caused bogus error messages to be
returned during migration. The attribute has been fixed, but the bug
persists if the copy-schema-to-ca.py script was run on Red Hat
Enterprise Linux 6.6 prior to running it on Red Hat Enterprise Linux
6.7. To work around this problem, manually copy
/usr/share/ipa/schema/05rfc2247.ldif to
/etc/dirsrv/slapd-PKI-IPA/schema/ and restart IdM. (BZ#1220788)

All ipa users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29f5d97e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ipa-admintools-3.0.0-47.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-client-3.0.0-47.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-python-3.0.0-47.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-3.0.0-47.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-selinux-3.0.0-47.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-trust-ad-3.0.0-47.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
