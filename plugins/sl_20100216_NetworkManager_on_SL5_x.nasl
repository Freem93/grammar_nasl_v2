#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60734);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-4144", "CVE-2009-4145");

  script_name(english:"Scientific Linux Security Update : NetworkManager on SL5.x i386/x86_64");
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
"CVE-2009-4145 NetworkManager: information disclosure by
nm-connection-editor

CVE-2009-4144 NetworkManager: WPA enterprise network not verified when
certificate is removed

A missing network certificate verification flaw was found in
NetworkManager. If a user created a WPA Enterprise or 802.1x wireless
network connection that was verified using a Certificate Authority
(CA) certificate, and then later removed that CA certificate file,
NetworkManager failed to verify the identity of the network on the
following connection attempts. In these situations, a malicious
wireless network spoofing the original network could trick a user into
disclosing authentication credentials or communicating over an
untrusted network. (CVE-2009-4144)

An information disclosure flaw was found in NetworkManager's
nm-connection-editor D-Bus interface. If a user edited network
connection options using nm-connection-editor, a summary of those
changes was broadcasted over the D-Bus message bus, possibly
disclosing sensitive information (such as wireless network
authentication credentials) to other local users. (CVE-2009-4145)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1002&L=scientific-linux-errata&T=0&P=1034
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4408be68"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(200, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"NetworkManager-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-devel-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-glib-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-glib-devel-0.7.0-9.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-gnome-0.7.0-9.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
