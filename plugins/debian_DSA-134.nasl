#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-134. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(14971);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/05/17 23:41:28 $");

  script_cve_id("CVE-2002-0639", "CVE-2002-0640");
  script_bugtraq_id(5093);
  script_osvdb_id(839, 6245);
  script_xref(name:"CERT", value:"369347");
  script_xref(name:"DSA", value:"134");

  script_name(english:"Debian DSA-134-4 : ssh - remote exploit");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ISS X-Force released an advisory about an OpenSSH 'Remote Challenge
Vulnerability'. Unfortunately, the advisory was incorrect on some
points, leading to widespread confusion about the impact of this
vulnerability. No version of OpenSSH in Debian is affected by the SKEY
and BSD_AUTH authentication methods described in the ISS advisory.
However, Debian does include OpenSSH servers with the PAM feature
described as vulnerable in the later advisory by the OpenSSH team.
(This vulnerable feature is authentication using PAM via the
keyboard-interactive mechanism [kbdint].) This vulnerability affects
OpenSSH versions 2.3.1 through 3.3. No exploit is currently known for
the PAM/kbdint vulnerability, but the details are publicly known. All
of these vulnerabilities were corrected in OpenSSH 3.4.

In addition to the vulnerabilities fixes outlined above, our OpenSSH
packages version 3.3 and higher support the new privilege separation
feature from Niels Provos, which changes ssh to use a separate
non-privileged process to handle most of the work. Vulnerabilities in
the unprivileged parts of OpenSSH will lead to compromise of an
unprivileged account restricted to an empty chroot, rather than a
direct root compromise. Privilege separation should help to mitigate
the risks of any future OpenSSH compromise.

Debian 2.2 (potato) shipped with an ssh package based on OpenSSH
1.2.3, and is not vulnerable to the vulnerabilities covered by this
advisory. Users still running a version 1.2.3 ssh package do not have
an immediate need to upgrade to OpenSSH 3.4. Users who upgraded to the
OpenSSH version 3.3 packages released in previous iterations of
DSA-134 should upgrade to the new version 3.4 OpenSSH packages, as the
version 3.3 packages are vulnerable. We suggest that users running
OpenSSH 1.2.3 consider a move to OpenSSH 3.4 to take advantage of the
privilege separation feature. (Though, again, we have no specific
knowledge of any vulnerability in OpenSSH 1.2.3. Please carefully read
the caveats listed below before upgrading from OpenSSH 1.2.3.) We
recommend that any users running a back-ported version of OpenSSH
version 2.0 or higher on potato move to OpenSSH 3.4.

The current pre-release version of Debian (woody) includes an OpenSSH
version 3.0.2p1 package (ssh), which is vulnerable to the PAM/kbdint
problem described above. We recommend that users upgrade to OpenSSH
3.4 and enable privilege separation. Please carefully read the release
notes below before upgrading. Updated packages for ssh-krb5 (an
OpenSSH package supporting kerberos authentication) are currently
being developed. Users who cannot currently upgrade their OpenSSH
packages may work around the known vulnerabilities by disabling the
vulnerable features: make sure the following lines are uncommented and
present in /etc/ssh/sshd_config and restart ssh

  PAMAuthenticationViaKbdInt no ChallengeResponseAuthentication no

There should be no other PAMAuthenticationViaKbdInt or
ChallengeResponseAuthentication entries in sshd_config.

That concludes the vulnerability section of this advisory. What
follows are release notes related to the OpenSSH 3.4 package and the
privilege separation feature. URLs for the OpenSSH 3.4 packages are at
the bottom.

Some notes on possible issues associated with this upgrade :

  - This package introduces a new account called `sshd' that
    is used in the privilege separation code. If no sshd
    account exists the package will try to create one. If
    the account already exists it will be re-used. If you do
    not want this to happen you will have to fix this
    manually.
  - (relevant for potato only) This update adds a back-port
    of version 0.9.6c of the SSL library. This means you
    will have to upgrade the libssl0.9.6 package as well.

  - (relevant for potato only) This update uses version 2 of
    the SSH protocol by default (even if configured to
    support version 1 of the SSH protocol). This can break
    existing setups where RSA authentication is used. You
    will either have to

    - add -1 to the ssh invocation to keep using SSH
      protocol 1 and your existing keys, or
    - change the Protocol line in /etc/ssh/ssh_config
      and/or/etc/ssh/sshd_config to 'Protocol 1,2' to try
      protocol 1 before protocol 2, or

    - create new rsa or dsa keys for SSH protocol 2

  - sshd defaults to enabling privilege separation, even if
    you do not explicitly enable it in /etc/ssh/sshd_config.
  - ssh fall-back to rsh is no longer available.

  - (relevant for potato only) Privilege separation does not
    currently work with Linux 2.0 kernels.

  - Privilege separation does not currently work with PAM
    authentication via the KeyboardInteractive mechanism.

  - Privilege separation causes some PAM modules which
    expect to run with root privileges to fail.

  - If for some reason you cannot use privilege separation
    at this time due to one of the issues described above,
    you can disable it by adding 'UsePrivilegeSeparation no'
    to your/etc/ssh/sshd_config file.

Some issues from previous OpenSSH 3.3p1 packages corrected in this
advisory (not a complete changelog) :

  - (relevant for potato only) the installation question,
    'do you want to allow protocol 2 only' no longer
    defaults to 'yes' for potato packages. Users who
    answered yes to this question and also chose to
    regenerate their sshd_config file found that they could
    no longer connect to their server via protocol 1. See
    /usr/doc/ssh/README.Debian for instructions on how to
    enable protocol 1 if caught in this situation. Since the
    default in the potato packages is now 'no', this should
    not be an issue for people upgrading from version 1.2.3
    in the future.
  - (relevant for potato only) the ssh package no longer
    conflicts with rsh-server, nor does it provide an rsh
    alternative

  - installation will no longer fail if users choose to
    generate protocol 1 keys

Again, we regret having to release packages with larger changes and
less testing than is our usual practice; given the potential severity
and non-specific nature of the original threat we decided that our
users were best served by having packages available for evaluation as
quickly as possible. We will send additional information as it comes
to us, and will continue to work on the outstanding issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-134"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected ssh package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"2.2", prefix:"libssl-dev", reference:"0.9.6c-0.potato.1")) flag++;
if (deb_check(release:"2.2", prefix:"libssl0.9.6", reference:"0.9.6c-0.potato.1")) flag++;
if (deb_check(release:"2.2", prefix:"openssl", reference:"0.9.6c-0.potato.1")) flag++;
if (deb_check(release:"2.2", prefix:"ssh", reference:"3.4p1-0.0potato1")) flag++;
if (deb_check(release:"2.2", prefix:"ssh-askpass-gnome", reference:"3.4p1-0.0potato1")) flag++;
if (deb_check(release:"2.2", prefix:"ssleay", reference:"0.9.6c-0.potato.1")) flag++;
if (deb_check(release:"3.0", prefix:"ssh", reference:"3.4p1-0.0woody1")) flag++;
if (deb_check(release:"3.0", prefix:"ssh-askpass-gnome", reference:"3.4p1-0.0woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
