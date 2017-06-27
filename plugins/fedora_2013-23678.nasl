#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-23678.
#

include("compat.inc");

if (description)
{
  script_id(71767);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 21:47:14 $");

  script_bugtraq_id(64424);
  script_xref(name:"FEDORA", value:"2013-23678");

  script_name(english:"Fedora 18 : gnupg-1.4.16-2.fc18 (2013-23678)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"What's New ===========

  - Fixed the RSA Key Extraction via Low-Bandwidth Acoustic
    Cryptanalysis attack as described by Genkin, Shamir, and
    Tromer. See
    <http://www.cs.tau.ac.il/~tromer/acoustic/>.[CVE-2013-45
    76]

  - Put only the major version number by default into
    armored output.

  - Do not create a trustdb file if --trust-model=always is
    used.

  - Print the keyid for key packets with --list-packets.

  - Changed modular exponentiation algorithm to recover from
    a small performance loss due to a change in 1.4.14.

Impact of the security problem ==============================

CVE-2013-4576 has been assigned to this security bug.

The paper describes two attacks.The first attack allows to distinguish
keys: An attacker is able to notice which key is currently used for
decryption.This is in general not a problem but may be used to reveal
the information that a message, encrypted to a commonly not used key,
has been received by the targeted machine.We do not have a software
solution to mitigate this attack.

The second attack is more serious. It is an adaptive chosen ciphertext
attack to reveal the private key. A possible scenario is that the
attacker places a sensor (for example a standard smartphone) in the
vicinity of the targeted machine. That machine is assumed to do
unattended RSA decryption of received mails, for example by using a
mail client which speeds up browsing by opportunistically decrypting
mails expected to be read soon.While listening to the acoustic
emanations of the targeted machine, the smartphone will send new
encrypted messages to that machine and re-construct the private key
bit by bit.A 4096 bit RSA key used on a laptop can be revealed within
an hour.

GnuPG 1.4.16 avoids this attack by employing RSA blinding during
decryption.GnuPG 2.x and current Gpg4win versions make use of
Libgcrypt which employs RSA blinding anyway and are thus not
vulnerable.

For the highly interesting research on acoustic cryptanalysis and the
details of the attack see http://www.cs.tau.ac.il/~tromer/acoustic/ .

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cs.tau.ac.il/~tromer/acoustic/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1044402"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/125340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58816af9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gnupg package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"gnupg-1.4.16-2.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg");
}
