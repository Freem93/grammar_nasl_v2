#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29517);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2012/05/17 11:20:15 $");

  script_cve_id("CVE-2005-4835", "CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180", "CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");

  script_name(english:"SuSE 10 Security Update : madwifi (ZYPP Patch Number 3897)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The madwifi driver and userland packages were updated to 0.9.3.1.
Please note that while the RPM version still says '0.9.3', the content
is the 0.9.3.1 version.

This updates fixes following security problems :

  - The 802.11 network stack in net80211/ieee80211_input.c
    in MadWifi before 0.9.3.1 allows remote attackers to
    cause a denial of service (system hang) via a crafted
    length field in nested 802.3 Ethernet frames in Fast
    Frame packets, which results in a NULL pointer
    dereference. (CVE-2007-2829)

  - The ath_beacon_config function in if_ath.c in MadWifi
    before 0.9.3.1 allows remote attackers to cause a denial
    of service (system crash) via crafted beacon interval
    information when scanning for access points, which
    triggers a divide-by-zero error. (CVE-2007-2830)

  - Array index error in the (1)
    ieee80211_ioctl_getwmmparams and (2)
    ieee80211_ioctl_setwmmparams functions in
    net80211/ieee80211_wireless.c in MadWifi before 0.9.3.1
    allows local users to cause a denial of service (system
    crash), possibly obtain kernel memory contents, and
    possibly execute arbitrary code via a large negative
    array index value. (CVE-2007-2831)

'remote attackers' are attackers within range of the WiFi reception of
the card.

Please note that the problems fixed in 0.9.3 were fixed by the madwifi
Version upgrade to 0.9.3 in SLE10 Service Pack 1. (CVE-2005-4835 /
CVE-2006-7177 / CVE-2006-7178 / CVE-2006-7179 / CVE-2006-7180)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2005-4835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-2831.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3897.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, reference:"madwifi-0.9.3-6.11")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"madwifi-kmp-default-0.9.3_2.6.16.46_0.16-6.11")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"madwifi-kmp-smp-0.9.3_2.6.16.46_0.16-6.11")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"madwifi-kmp-bigsmp-0.9.3_2.6.16.46_0.16-6.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
