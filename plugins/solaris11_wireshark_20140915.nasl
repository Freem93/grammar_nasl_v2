#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80815);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_buffer_errors_vulnerabilities_in3)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - The dissect_log function in plugins/irda/packet-irda.c
    in the IrDA dissector in Wireshark 1.10.x before 1.10.9
    does not properly strip '\n' characters, which allows
    remote attackers to cause a denial of service (buffer
    underflow and application crash) via a crafted packet.
    (CVE-2014-5161)

  - The read_new_line function in wiretap/catapult_dct2000.c
    in the Catapult DCT2000 dissector in Wireshark 1.10.x
    before 1.10.9 does not properly strip '\ n' and '\r'
    characters, which allows remote attackers to cause a
    denial of service (off-by-one buffer underflow and
    application crash) via a crafted packet. (CVE-2014-5162)

  - The APN decode functionality in (1)
    epan/dissectors/packet-gtp.c and (2) epan/
    dissectors/packet-gsm_a_gm.c in the GTP and GSM
    Management dissectors in Wireshark 1.10.x before 1.10.9
    does not completely initialize a certain buffer, which
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2014-5163)

  - The rlc_decode_li function in
    epan/dissectors/packet-rlc.c in the RLC dissector in
    Wireshark 1.10.x before 1.10.9 initializes a certain
    structure member only after this member is used, which
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2014-5164)

  - The dissect_ber_constrained_bitstring function in
    epan/dissectors/packet-ber.c in the ASN.1 BER dissector
    in Wireshark 1.10.x before 1.10.9 does not properly
    validate padding values, which allows remote attackers
    to cause a denial of service (buffer underflow and
    application crash) via a crafted packet. (CVE-2014-5165)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_buffer_errors_vulnerabilities_in3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dc5c4a2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.2.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^wireshark$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.2.0.5.0", sru:"SRU 11.2.2.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
