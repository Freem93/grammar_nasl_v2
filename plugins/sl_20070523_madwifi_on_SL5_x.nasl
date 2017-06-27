#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60188);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_name(english:"Scientific Linux Security Update : madwifi on SL5.x, SL4.x i386/x86_64");
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
"Madwifi 0.9.3.1 Release note:
http://madwifi.org/wiki/news/20070523/release-0-9-3-1-fixes-three-secu
rity-issue

Security fixes in 0.9.3.1 :

  - http://madwifi.org/ticket/1270 In the madwifi/ath
    component if_ath.c handles the beacon configuration
    related initialization task both for clients and aps in
    the function ath_beacon_config(). The function uses
    macro 'howmany' which performs divide operation. The
    macro is used without ensuring that the
    argument(denominator 'intval') could be zero. The divide
    by zero condition can be triggered externally using a
    malformed packet.

  - http://madwifi.org/ticket/1335 There is a vulnerability
    in packet parsing code whereby a remote attacker can
    craft a malicious packet that will DoS the system. Due
    to improper sanitization of nested 802.3 Ethernet frame
    length fields in Fast Frame packets, the MadWifi driver
    is vulnerable to a remote kernel denial of service. The
    problem is that the frame length is read directly from
    the attackers packet without validation. The attacker
    can specify a length so that after the skb_pull
    operation skb1 is less than sizeof(ethernet_header).
    When skb_pull is called again on skb1 in athff_decap it
    will return NULL. This results in a NULL dereference
    later on in the function.

  - http://madwifi.org/ticket/1334 A restricted local user
    can make an unprivileged I/O control call to the
    driver's ieee80211_ioctl_getwmmparams. This function
    accepts an array index from the user, which is validated
    incorrectly. The function checks that the index supplied
    by the user is less than a maximum value, but does not
    check if the index is less than 0. A local attacker can
    specify a large negative number which will pass the
    check, and cause an error in the array dereference.

NOTE: The version number 0.9.3.1 is actually lower than the version
number shipped in Scientific Linux 4.x. This is correct. This really
is the latest version of madwifi. We have adjusted the rpm's so that
they can handle this."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=1099
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07188c45"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://madwifi.org/ticket/1270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://madwifi.org/ticket/1334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://madwifi.org/ticket/1335"
  );
  # http://madwifi.org/wiki/news/20070523/release-0-9-3-1-fixes-three-security-issue
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?466a3814"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-42.0.10.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-2.6.9-42.0.10.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-2.6.9-42.0.10.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-42.0.10.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-42.0.3.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-2.6.9-42.0.3.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-2.6.9-42.0.3.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-42.0.3.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-42.0.8.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-2.6.9-42.0.8.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-2.6.9-42.0.8.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-42.0.8.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-55.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-2.6.9-55.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-2.6.9-55.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-2.6.9-55.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-42.0.10.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.9-42.0.10.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-hal-2.6.9-42.0.10.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-42.0.10.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-42.0.3.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.9-42.0.3.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-hal-2.6.9-42.0.3.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-42.0.3.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-42.0.8.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.9-42.0.8.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-hal-2.6.9-42.0.8.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-42.0.8.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-55.EL-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.9-55.ELhugemem-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-madwifi-hal-2.6.9-55.ELlargesmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-madwifi-hal-2.6.9-55.ELsmp-0.9.3.1-10.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"madwifi-0.9.3.1-10.sl4")) flag++;

if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-8.1.3.el5-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-2.6.18-8.1.3.el5PAE-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-8.1.3.el5xen-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-8.1.4.el5-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-2.6.18-8.1.4.el5PAE-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-8.1.4.el5xen-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-8.1.3.el5-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.18-8.1.3.el5PAE-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-8.1.3.el5xen-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-8.1.4.el5-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.18-8.1.4.el5PAE-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-8.1.4.el5xen-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"madwifi-0.9.3.1-11.sl5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
