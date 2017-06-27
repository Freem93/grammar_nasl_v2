#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80904);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2014-3566", "CVE-2014-6549", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412", "CVE-2015-0437");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL6.x i386/x86_64 (POODLE)");
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
"Multiple flaws were found in the way the Hotspot component in OpenJDK
verified bytecode from the class files, and in the way this component
generated code for bytecode. An untrusted Java application or applet
could possibly use these flaws to bypass Java sandbox restrictions.
(CVE-2014-6601, CVE-2015-0437)

Multiple improper permission check issues were discovered in the
JAX-WS, Libraries, and RMI components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2015-0412, CVE-2014-6549, CVE-2015-0408)

A flaw was found in the way the Hotspot garbage collector handled
phantom references. An untrusted Java application or applet could use
this flaw to corrupt the Java Virtual Machine memory and, possibly,
execute arbitrary code, bypassing Java sandbox restrictions.
(CVE-2015-0395)

A flaw was found in the way the DER (Distinguished Encoding Rules)
decoder in the Security component in OpenJDK handled negative length
values. A specially crafted, DER-encoded input could cause a Java
application to enter an infinite loop when decoded. (CVE-2015-0410)

A flaw was found in the way the SSL 3.0 protocol handled padding bytes
when decrypting messages that were encrypted using block ciphers in
cipher block chaining (CBC) mode. This flaw could possibly allow a
man-in-the- middle (MITM) attacker to decrypt portions of the cipher
text using a padding oracle attack. (CVE-2014-3566)

It was discovered that the SSL/TLS implementation in the JSSE
component in OpenJDK failed to properly check whether the
ChangeCipherSpec was received during the SSL/TLS connection handshake.
An MITM attacker could possibly use this flaw to force a connection to
be established without encryption being enabled. (CVE-2014-6593)

An information leak flaw was found in the Swing component in OpenJDK.
An untrusted Java application or applet could use this flaw to bypass
certain Java sandbox restrictions. (CVE-2015-0407)

A NULL pointer dereference flaw was found in the MulticastSocket
implementation in the Libraries component of OpenJDK. An untrusted
Java application or applet could possibly use this flaw to bypass
certain Java sandbox restrictions. (CVE-2014-6587)

Multiple boundary check flaws were found in the font parsing code in
the 2D component in OpenJDK. A specially crafted font file could allow
an untrusted Java application or applet to disclose portions of the
Java Virtual Machine memory. (CVE-2014-6585, CVE-2014-6591)

Multiple insecure temporary file use issues were found in the way the
Hotspot component in OpenJDK created performance statistics and error
log files. A local attacker could possibly make a victim using OpenJDK
overwrite arbitrary files using a symlink attack. (CVE-2015-0383)

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1501&L=scientific-linux-errata&T=0&P=1922
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da9099c7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-1.8.0.31-1.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.31-1.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-1.8.0.31-1.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-1.8.0.31-1.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-1.8.0.31-1.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.31-1.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-1.8.0.31-1.b13.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
