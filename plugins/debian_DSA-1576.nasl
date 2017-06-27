#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1576. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(32377);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2008-0166");
  script_bugtraq_id(29179);
  script_osvdb_id(45029);
  script_xref(name:"DSA", value:"1576");

  script_name(english:"Debian DSA-1576-1 : openssh - predictable random number generator");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The recently announced vulnerability in Debian's openssl package (
DSA-1571-1, CVE-2008-0166 ) indirectly affects OpenSSH. As a result,
all user and host keys generated using broken versions of the openssl
package must be considered untrustworthy, even after the openssl
update has been applied.

1. Install the security updates

This update contains a dependency on the openssl update and will
automatically install a corrected version of the libssl0.9.8 package,
and a new package openssh-blacklist.

Once the update is applied, weak user keys will be automatically
rejected where possible (though they cannot be detected in all cases).
If you are using such keys for user authentication, they will
immediately stop working and will need to be replaced (see step 3).

OpenSSH host keys can be automatically regenerated when the OpenSSH
security update is applied. The update will prompt for confirmation
before taking this step.

2. Update OpenSSH known_hosts files

The regeneration of host keys will cause a warning to be displayed
when connecting to the system using SSH until the host key is updated
in the known_hosts file. The warning will look like this :

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @ WARNING:
REMOTE HOST IDENTIFICATION HAS CHANGED! @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ IT IS
POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY! Someone could be
eavesdropping on you right now (man-in-the-middle attack)! It is also
possible that the RSA host key has just been changed.

In this case, the host key has simply been changed, and you should
update the relevant known_hosts file as indicated in the error
message. It is recommended that you use a trustworthy channel to
exchange the server key. It is found in the file
/etc/ssh/ssh_host_rsa_key.pub on the server; it's fingerprint can be
printed using the command :

ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub

In addition to user-specific known_hosts files, there may be a
system-wide known hosts file /etc/ssh/ssh_known_hosts. This is file is
used both by the ssh client and by sshd for the hosts.equiv
functionality. This file needs to be updated as well.

3. Check all OpenSSH user keys

The safest course of action is to regenerate all OpenSSH user keys,
except where it can be established to a high degree of certainty that
the key was generated on an unaffected system.

Check whether your key is affected by running the ssh-vulnkey tool,
included in the security update. By default, ssh-vulnkey will check
the standard location for user keys (~/.ssh/id_rsa, ~/.ssh/id_dsa and
~/.ssh/identity), your authorized_keys file (~/.ssh/authorized_keys
and ~/.ssh/authorized_keys2), and the system's host keys
(/etc/ssh/ssh_host_dsa_key and /etc/ssh/ssh_host_rsa_key).

To check all your own keys, assuming they are in the standard
locations (~/.ssh/id_rsa, ~/.ssh/id_dsa, or ~/.ssh/identity) :

ssh-vulnkey

To check all keys on your system :

sudo ssh-vulnkey -a

To check a key in a non-standard location :

ssh-vulnkey /path/to/key

If ssh-vulnkey says 'Unknown (no blacklist information)', then it has
no information about whether that key is affected. In this case, you
can examine the modification time (mtime) of the file using 'ls -l'.
Keys generated before September 2006 are not affected. Keep in mind
that, although unlikely, backup procedures may have changed the file
date back in time (or the system clock may have been incorrectly set).
If in doubt, generate a new key and remove the old one from any
servers.

4. Regenerate any affected user keys

OpenSSH keys used for user authentication must be manually
regenerated, including those which may have since been transferred to
a different system after being generated.

New keys can be generated using ssh-keygen, e.g. :

    $ ssh-keygen Generating public/private rsa key pair. Enter file in
    which to save the key (/home/user/.ssh/id_rsa): Enter passphrase
    (empty for no passphrase): Enter same passphrase again: Your
    identification has been saved in /home/user/.ssh/id_rsa. Your
    public key has been saved in /home/user/.ssh/id_rsa.pub. The key
    fingerprint is: 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
    user@host

5. Update authorized_keys files (if necessary)

Once the user keys have been regenerated, the relevant public keys
must be propagated to any authorized_keys files (and authorized_keys2
files, if applicable) on remote systems. Be sure to delete the lines
containing old keys from those files.

In addition to countermeasures to mitigate the randomness
vulnerability, this OpenSSH update fixes several other vulnerabilities
:

 CVE-2008-1483: Timo Juhani Lindfors discovered that, when using X11
 forwarding, the SSH client selects an X11 forwarding port without
 ensuring that it can be bound on all address families. If the system
 is configured with IPv6 (even if it does not have working IPv6
 connectivity), this could allow a local attacker on the remote server
 to hijack X11 forwarding.

 CVE-2007-4752: Jan Pechanec discovered that ssh falls back to
 creating a trusted X11 cookie if creating an untrusted cookie fails,
 potentially exposing the local display to a malicious remote server
 when using X11 forwarding."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1576"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh packages and take the measures indicated above.

For the stable distribution (etch), these problems have been fixed in
version 4.3p2-9etch1. Currently, only a subset of all supported
architectures have been built; further updates will be provided when
they become available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"openssh-blacklist", reference:"0.1.1")) flag++;
if (deb_check(release:"4.0", prefix:"openssh-client", reference:"4.3p2-9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openssh-server", reference:"4.3p2-9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ssh", reference:"4.3p2-9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ssh-askpass-gnome", reference:"4.3p2-9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ssh-krb5", reference:"4.3p2-9etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
