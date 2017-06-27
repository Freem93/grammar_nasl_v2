#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85197);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2010-5312", "CVE-2012-6662");

  script_name(english:"Scientific Linux Security Update : ipa on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Note: The IdM version provided by this update no longer uses jQuery.

Bug fixes :

  - The ipa-server-install, ipa-replica-install, and
    ipa-client-install utilities are not supported on
    machines running in FIPS-140 mode. Previously, IdM did
    not warn users about this. Now, IdM does not allow
    running the utilities in FIPS-140 mode, and displays an
    explanatory message.

  - If an Active Directory (AD) server was specified or
    discovered automatically when running the
    ipa-client-install utility, the utility produced a
    traceback instead of informing the user that an IdM
    server is expected in this situation. Now,
    ipa-client-install detects the AD server and fails with
    an explanatory message.

  - When IdM servers were configured to require the TLS
    protocol version 1.1 (TLSv1.1) or later in the httpd
    server, the ipa utility failed. With this update,
    running ipa works as expected with TLSv1.1 or later.

  - In certain high-load environments, the Kerberos
    authentication step of the IdM client installer can
    fail. Previously, the entire client installation failed
    in this situation. This update modifies ipa-client-
    install to prefer the TCP protocol over the UDP protocol
    and to retry the authentication attempt in case of
    failure.

  - If ipa-client-install updated or created the
    /etc/nsswitch.conf file, the sudo utility could
    terminate unexpectedly with a segmentation fault. Now,
    ipa-client-install puts a new line character at the end
    of nsswitch.conf if it modifies the last line of the
    file, fixing this bug.

  - The ipa-client-automount utility failed with the
    'UNWILLING_TO_PERFORM' LDAP error when the
    nsslapd-minssf Red Hat Directory Server configuration
    parameter was set to '1'. This update modifies
    ipa-client-automount to use encrypted connection for
    LDAP searches by default, and the utility now finishes
    successfully even with nsslapd-minssf specified.

  - If installing an IdM server failed after the Certificate
    Authority (CA) installation, the 'ipa-server-install
    --uninstall' command did not perform a proper cleanup.
    After the user issued 'ipa-server-install --uninstall'
    and then attempted to install the server again, the
    installation failed. Now, 'ipa-server-install
    --uninstall' removes the CA-related files in the
    described situation, and ipa-server-install no longer
    fails with the mentioned error message.

  - Running ipa-client-install added the 'sss' entry to the
    sudoers line in nsswitch.conf even if 'sss' was already
    configured and the entry was present in the file.
    Duplicate 'sss' then caused sudo to become unresponsive.
    Now, ipa-client-install no longer adds 'sss' if it is
    already present in nsswitch.conf.

  - After running ipa-client-install, it was not possible to
    log in using SSH under certain circumstances. Now,
    ipa-client-install no longer corrupts the sshd_config
    file, and the sshd service can start as expected, and
    logging in using SSH works in the described situation.

  - An incorrect definition of the dc attribute in the
    /usr/share/ipa/05rfc2247.ldif file caused bogus error
    messages to be returned during migration. The attribute
    has been fixed, but the bug persists if the
    copy-schema-to-ca.py script was run on Scientific Linux
    6.6 prior to running it on Scientific Linux 6.7. To work
    around this problem, manually copy
    /usr/share/ipa/schema/05rfc2247.ldif to /etc/dirsrv
    /slapd-PKI-IPA/schema/ and restart IdM."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=2807
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c3be150"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"ipa-admintools-3.0.0-47.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-client-3.0.0-47.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-debuginfo-3.0.0-47.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-python-3.0.0-47.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-3.0.0-47.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-selinux-3.0.0-47.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-trust-ad-3.0.0-47.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
