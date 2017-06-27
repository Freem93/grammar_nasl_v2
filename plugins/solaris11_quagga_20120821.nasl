#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80752);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/21 15:53:44 $");

  script_cve_id("CVE-2012-0248", "CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255", "CVE-2012-1820");

  script_name(english:"Oracle Solaris Third-Party Patch Update : quagga (cve_2012_1820_denial_of)");
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

  - ImageMagick 6.7.5-7 and earlier allows remote attackers
    to cause a denial of service (infinite loop and hang)
    via a crafted image whose IFD contains IOP tags that all
    reference the beginning of the IDF. (CVE-2012-0248)

  - Buffer overflow in the ospf_ls_upd_list_lsa function in
    ospf_packet.c in the OSPFv2 implementation in ospfd in
    Quagga before 0.99.20.1 allows remote attackers to cause
    a denial of service (assertion failure and daemon exit)
    via a Link State Update (aka LS Update) packet that is
    smaller than the length specified in its header.
    (CVE-2012-0249)

  - Buffer overflow in the OSPFv2 implementation in ospfd in
    Quagga before 0.99.20.1 allows remote attackers to cause
    a denial of service (daemon crash) via a Link State
    Update (aka LS Update) packet containing a network-LSA
    link-state advertisement for which the data-structure
    length is smaller than the value in the Length header
    field. (CVE-2012-0250)

  - The BGP implementation in bgpd in Quagga before
    0.99.20.1 does not properly use message buffers for OPEN
    messages, which allows remote attackers to cause a
    denial of service (assertion failure and daemon exit)
    via a message associated with a malformed Four-octet AS
    Number Capability (aka AS4 capability). (CVE-2012-0255)

  - The bgp_capability_orf function in bgpd in Quagga
    0.99.20.1 and earlier allows remote attackers to cause a
    denial of service (assertion failure and daemon exit) by
    leveraging a BGP peering relationship and sending a
    malformed Outbound Route Filtering (ORF) capability TLV
    in an OPEN message. (CVE-2012-1820)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2012_1820_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_quagga
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c52897fe"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 10.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:quagga");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/21");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^quagga$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.10.0.5.0", sru:"SRU 10.5a") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : quagga\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "quagga");
