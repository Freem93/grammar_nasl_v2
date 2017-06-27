#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-983.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75233);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_name(english:"openSUSE Security Update : ca-certificates-mozilla (openSUSE-SU-2013:1891-1)");
  script_summary(english:"Check for the openSUSE-2013-983 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla CA certificates package was updated to match the current
Mozilla revision 1.95 of certdata.txt.

It blacklists some misused certificate authorities, adds some new and
adjusts some others.

On openSUSE 13.1 a problem with names was also fixed.

  - distrust: AC DG Tresor SSL (bnc#854367)

  - new:
    CA_Disig_Root_R1:2.9.0.195.3.154.238.80.144.110.40.crt
    server auth, code signing, email signing

  - new:
    CA_Disig_Root_R2:2.9.0.146.184.136.219.176.138.193.99.cr
    t server auth, code signing, email signing

  - new:
    China_Internet_Network_Information_Center_EV_Certificate
    s_Root:2.4.72.159.0.1.crt server auth

  - changed:
    Digital_Signature_Trust_Co._Global_CA_1:2.4.54.112.21.15
    0.crt removed code signing and server auth abilities

  - changed:
    Digital_Signature_Trust_Co._Global_CA_3:2.4.54.110.211.2
    06.crt removed code signing and server auth abilities

  - new: D-TRUST_Root_Class_3_CA_2_2009:2.3.9.131.243.crt
    server auth

  - new: D-TRUST_Root_Class_3_CA_2_EV_2009:2.3.9.131.244.crt
    server auth

  - removed:
    Equifax_Secure_eBusiness_CA_2:2.4.55.112.207.181.crt

  - new: PSCProcert:2.1.11.crt server auth, code signing,
    email signing

  - new:
    Swisscom_Root_CA_2:2.16.30.158.40.232.72.242.229.239.195
    .124.74.30.90.24.103.182.crt server auth, code signing,
    email signing

  - new:
    Swisscom_Root_EV_CA_2:2.17.0.242.250.100.226.116.99.211.
    141.253.16.29.4.31.118.202.88.crt server auth, code
    signing

  - changed:
    TC_TrustCenter_Universal_CA_III:2.14.99.37.0.1.0.2.20.14
    1.51.21.2.228.108.244.crt removed all abilities

  - new:
    TURKTRUST_Certificate_Services_Provider_Root_2007:2.1.1.
    crt server auth, code signing

  - changed: TWCA_Root_Certification_Authority:2.1.1.crt
    added code signing ability"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854367"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ca-certificates-mozilla package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ca-certificates-mozilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2|SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"ca-certificates-mozilla-1.95-8.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ca-certificates-mozilla-1.95-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ca-certificates-mozilla-1.95-3.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ca-certificates-mozilla");
}
